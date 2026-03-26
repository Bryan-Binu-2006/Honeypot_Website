/* Internal tooling bundle accidentally shipped to production (simulated). */
(function () {
  const hiddenEndpoints = [
    "/api/v2/internal/users",
    "/internal/k8s/dashboard",
    "/internal/admin-service",
    "/internal/ci/pipeline",
    "/internal/vault/secrets"
  ];

  const debugTokens = {
    fallbackJwtHint: "forged_admin_token",
    internalKeyHint: "adminkey_int_7fce381d"
  };

  window.__CYBERSHIELD_INTERNAL__ = {
    hiddenEndpoints,
    debugTokens,
    note: "This object should never be present in public assets.",
  };
})();
