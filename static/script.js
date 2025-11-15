
// ADMIN

// JS: Search + Sort 
  function filterTable() {
    const input = document.getElementById("searchInput").value.toLowerCase();
    const rows = document.querySelectorAll("#claimsTable tbody tr");
    rows.forEach(row => {
      row.style.display = row.innerText.toLowerCase().includes(input) ? "" : "none";
    });
  }

  function sortTable(n) {
    const table = document.getElementById("claimsTable");
    let switching = true;
    let dir = "asc";
    while (switching) {
      switching = false;
      const rows = table.rows;
      for (let i = 1; i < rows.length - 1; i++) {
        const x = rows[i].getElementsByTagName("td")[n];
        const y = rows[i + 1].getElementsByTagName("td")[n];
        let shouldSwitch = false;
        if (dir === "asc" && x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
          shouldSwitch = true;
          break;
        } else if (dir === "desc" && x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
          shouldSwitch = true;
          break;
        }
      }
      if (shouldSwitch) {
        rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
        switching = true;
      } else if (dir === "asc") {
        dir = "desc";
        switching = true;
      }
    }
  }

// Claims

function filterStatus(status, event) {
  const rows = document.querySelectorAll("#claimsTable tbody tr");
  const buttons = document.querySelectorAll(".tab-btn");

  // Highlight active tab
  buttons.forEach(btn => btn.classList.remove("active"));
  if (event) event.target.classList.add("active");

  // Show or hide rows based on status
  rows.forEach(row => {
    const rowStatus = (row.getAttribute("data-status") || "").toLowerCase();
    if (status === "all" || rowStatus === status) {
      row.style.display = "";
    } else {
      row.style.display = "none";
    }
  });
}

// Items
function filterItems() {
  const search = document.getElementById("searchInput").value.toLowerCase();
  const status = document.getElementById("statusFilter").value;
  const cards = document.querySelectorAll(".item-card");

  cards.forEach(card => {
    const text = card.getAttribute("data-text");
    const cardStatus = card.getAttribute("data-status");
    const matchesText = text.includes(search);
    const matchesStatus = status === "all" || status === cardStatus;

    if (matchesText && matchesStatus) {
      card.style.display = "";
    } else {
      card.style.display = "none";
    }
  });
}


// Users
function filterTable() {
  const query = document.getElementById("searchInput").value.toLowerCase();
  const role = document.getElementById("roleFilter").value;
  const rows = document.querySelectorAll("#usersTable tbody tr");

  rows.forEach(row => {
    const text = row.innerText.toLowerCase();
    const rowRole = row.getAttribute("data-role");
    const matchText = text.includes(query);
    const matchRole = role === "all" || role === rowRole;
    row.style.display = (matchText && matchRole) ? "" : "none";
  });
}

function sortTable(n) {
  const table = document.getElementById("usersTable");
  let switching = true, dir = "asc";
  while (switching) {
    switching = false;
    const rows = table.rows;
    for (let i = 1; i < rows.length - 1; i++) {
      const x = rows[i].getElementsByTagName("td")[n];
      const y = rows[i + 1].getElementsByTagName("td")[n];
      let shouldSwitch = false;
      if (dir === "asc" && x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
        shouldSwitch = true; break;
      } else if (dir === "desc" && x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
        shouldSwitch = true; break;
      }
    }
    if (shouldSwitch) {
      rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
      switching = true;
    } else if (dir === "asc") {
      dir = "desc"; switching = true;
    }
  }
}



// Flash close button handler
document.addEventListener("click", function (e) {
  if (e.target.classList.contains("close-btn")) {
    const flash = e.target.parentElement;
    flash.style.opacity = "0";
    flash.style.transform = "translateY(-10px)";
    setTimeout(() => flash.remove(), 300);
  }
});


// Toggle password visibility 
function togglePassword() {
  const passwordInput = document.getElementById("password");
  const toggleIcon = document.querySelector(".toggle-password");
  const isHidden = passwordInput.type === "password";

  passwordInput.type = isHidden ? "text" : "password";
  toggleIcon.textContent = isHidden ? "🙈" : "👁️";
}


function togglePassword(fieldId, icon) {
  const input = document.getElementById(fieldId);
  const hidden = input.type === "password";

  input.type = hidden ? "text" : "password";
  icon.textContent = hidden ? "🙈" : "👁️";
}




  const statusSelect = document.getElementById("status");
  const securitySection = document.getElementById("security-section");
  const contactTitle = document.getElementById("contact-title");
  const contactDesc = document.getElementById("contact-desc");
  const contactNumber = document.getElementById("contact_number");
  const utpEmail = document.getElementById("utp_email");

  function toggleSections() {
    const status = statusSelect.value.toLowerCase();

    // Toggle security section
    securitySection.style.display = status === "found" ? "block" : "none";

    if (status === "found") {
      contactTitle.textContent = "Finder’s Contact Information";
      contactDesc.textContent = "This information will only be visible to admin until the claim is approved.";
      contactNumber.required = true;
      utpEmail.required = true;
    } else {
      contactTitle.textContent = "Owner’s Information";
      contactDesc.textContent = "Optional: provide your contact if you want admin or finder to reach you.";
      contactNumber.required = false;
      utpEmail.required = false;
    }
  }

  toggleSections();
  statusSelect.addEventListener("change", toggleSections);
