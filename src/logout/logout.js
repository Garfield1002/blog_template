/**
 * Logout handler.
 *
 * Clears the __Host-key and __Host-uid cookies, then redirects to /.
 */

(function () {
  document.cookie =
    "__Host-key=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; Secure; SameSite=Lax";
  document.cookie =
    "__Host-uid=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; Secure; SameSite=Lax";

  window.location.replace("/");
})();
