/**
 * Logout handler.
 *
 * Removes the stored blog credentials from localStorage, then redirects to /.
 */

(function () {
  localStorage.removeItem("static-blog-key");
  localStorage.removeItem("static-blog-uid");
  localStorage.removeItem("__Host-key");
  localStorage.removeItem("__Host-uid");

  var base = document.body.getAttribute("data-base") || ".";
  window.location.replace(base + "/");
})();
