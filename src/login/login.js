/**
 * Login form handler.
 *
 * Reads key + uid from the form, sets cookies, and redirects to /.
 */

(function () {
  var form = document.getElementById("login-form");
  var errorEl = document.getElementById("error");

  form.addEventListener("submit", function (e) {
    e.preventDefault();

    var key = document.getElementById("key-input").value.trim();
    var uid = document.getElementById("uid-input").value.trim();

    if (!key || !uid) {
      errorEl.textContent = "Both fields are required.";
      return;
    }

    // Validate key: unpadded base64url 32 bytes → always 43 characters.
    if (key.length !== 43 || !/^[A-Za-z0-9_-]+$/.test(key)) {
      errorEl.textContent = "Invalid key format.";
      return;
    }

    var expires = new Date();
    expires.setFullYear(expires.getFullYear() + 1);

    document.cookie =
      "__Host-key=" + encodeURIComponent(key) +
      "; expires=" + expires.toUTCString() +
      "; path=/" +
      "; Secure" +
      "; SameSite=Lax";

    document.cookie =
      "__Host-uid=" + encodeURIComponent(uid) +
      "; expires=" + expires.toUTCString() +
      "; path=/" +
      "; Secure" +
      "; SameSite=Lax";

    window.location.replace("/");
  });
})();
