"""Completability invariants for the multi-branch crown.

The crown (vault-keystone) accepts ONE credential per deep CORP branch so the
range completes ~10 genuinely different ways instead of collapsing onto a
single leaked token. These tests pin the two sides of that contract together:

1. every ``vault_token`` declared in a module manifest is accepted by the
   vault app, and the vault app accepts nothing else (anti-drift parity);
2. every token-holding branch is a CORP-zone module and is reachable in the
   trust graph from at least one initial-access vector (real completability,
   not just declaration);
3. the vault stays sealed without a token and the crown stays zone-isolated.
"""
import importlib.util
import os
import unittest

from keystone.manifest import discover_modules
from keystone import zones

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MODULES = os.path.join(ROOT, "modules")
VAULT_APP = os.path.join(MODULES, "vault-keystone", "app", "server.py")

# A range that claims "many different completable ways" needs at least this
# many independent branches to the crown. Bump only when adding real branches.
MIN_BRANCHES = 8


def _load_vault_app():
    spec = importlib.util.spec_from_file_location("keystone_vault_app", VAULT_APP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _trust_closure(manifests):
    """Modules reachable from any initial-access vector over enables edges."""
    closure = {m.id for m in manifests if m.is_initial_access}
    changed = True
    while changed:
        changed = False
        for m in manifests:
            if m.id in closure:
                for en in m.enables:
                    if en not in closure:
                        closure.add(en)
                        changed = True
    return closure


class TestVaultBranchParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifests = discover_modules(MODULES)
        cls.vault = _load_vault_app()
        cls.holders = {m.id: m for m in cls.manifests if m.vault_token}

    def test_many_independent_branches_declared(self):
        self.assertGreaterEqual(len(self.holders), MIN_BRANCHES)

    def test_manifest_tokens_and_vault_app_are_identical_sets(self):
        manifest_tokens = {m.vault_token["value"] for m in self.holders.values()}
        app_tokens = set(self.vault.VAULT_TOKENS)
        self.assertEqual(manifest_tokens, app_tokens,
                         "vault app token set and manifest vault_token values "
                         "have drifted — update one side")

    def test_every_branch_is_a_corp_zone_module(self):
        for mod_id, m in self.holders.items():
            self.assertEqual(m.network_zone, "corp",
                             f"{mod_id}: crown branch must be a CORP module")

    def test_vault_accepts_every_branch_token_and_rejects_junk(self):
        for tok in self.vault.VAULT_TOKENS:
            self.assertTrue(self.vault._valid_token(tok), tok)
        for junk in ("", None, "ks-vault-svc-WRONG", "admin", "X-Vault-Token",
                     "ks-vault-svc-7f3c210", 42):
            self.assertFalse(self.vault._valid_token(junk), junk)

    def test_every_branch_is_reachable_from_an_initial_access_vector(self):
        closure = _trust_closure(self.manifests)
        for mod_id in self.holders:
            self.assertIn(mod_id, closure,
                          f"{mod_id}: branch not reachable from any entry vector")

    def test_enables_mirrors_prereqs_everywhere(self):
        # The dashboard draws trust edges from ``enables`` only, so a module
        # listed as another's prereq must also appear in that module's enables
        # or the graph (and this closure test) silently drops the path.
        # Direction is prereq -> enables: a few one-way chain HINTS exist the
        # other way (gitleak-api -> meta-ssrf -> cache-open: a leaked key helps
        # at an entry module) and are intentionally not declared back, since
        # that would strip the target's initial-access status.
        by_id = {m.id: m for m in self.manifests}
        for m in self.manifests:
            for dep in m.prereqs:
                self.assertIn(m.id, by_id[dep].enables,
                              f"{dep} must list {m.id} in enables (it is a prereq)")

    def test_crown_prereqs_are_exactly_the_token_holding_branches(self):
        vault = next(m for m in self.manifests if m.id == "vault-keystone")
        self.assertEqual(set(vault.prereqs), set(self.holders),
                         "vault-keystone.prereqs must equal the set of modules "
                         "that declare a vault_token")

    def test_crown_reachable_from_initial_access(self):
        closure = _trust_closure(self.manifests)
        self.assertIn("vault-keystone", closure)

    def test_crown_stays_network_isolated(self):
        self.assertTrue(zones.crown_is_isolated(self.manifests))

    def test_vault_still_sealed_without_token(self):
        # The 401-without-token path must survive the multi-token change.
        self.assertFalse(self.vault._valid_token(""))
        with open(VAULT_APP, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("401", src)
        self.assertNotIn("list_directory", src)


if __name__ == "__main__":
    unittest.main()
