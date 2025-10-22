document.getElementById("cipherForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const button = document.getElementById("breakButton");
  const spinner = document.getElementById("spinner");
  const statusText = document.getElementById("statusText");
  const output = document.getElementById("output");
  const keyField = document.getElementById("key");
  const plaintextField = document.getElementById("plaintext");
  const formData = new FormData(e.target); // includes cipher_type automatically

  // Show spinner
  button.classList.add("hidden");
  spinner.classList.remove("hidden");
  output.classList.add("hidden");

  // Progress messages
  const statuses = [
    "Getting lengths...",
    "Constructing key...",
    "Decoding message...",
    "Done!"
  ];

  for (let i = 0; i < statuses.length; i++) {
    statusText.textContent = statuses[i];
    await new Promise((r) => setTimeout(r, 800));
  }

  // Debug: check what’s being sent
  console.log("Sending:", Object.fromEntries(formData.entries()));

  const response = await fetch("/", {
    method: "POST",
    body: formData
  });

  const data = await response.json();

  spinner.classList.add("hidden");
  button.classList.remove("hidden");
  output.classList.remove("hidden");

  keyField.textContent = data.key || "N/A";
  plaintextField.textContent = data.text || "Error decoding text";
});
