/**
 * Logout handler.
 *
 * Removes the __Host-key and __Host-uid items from localStorage, then redirects to /.
 */

(function () {
  localStorage.removeItem("__Host-key");
  localStorage.removeItem("__Host-uid");

  var base = document.body.getAttribute("data-base") || ".";
  window.location.replace(base + "/");
})();
