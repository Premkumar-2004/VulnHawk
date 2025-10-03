document.addEventListener("DOMContentLoaded", function () {
  // Elemente DOM
  const chatWindow = document.getElementById("chat-window");
  const closeChat = document.getElementById("close-chat");
  const chatMessages = document.getElementById("chat-messages");
  const fileInput = document.getElementById("pdfFile");
  const sendButton = document.getElementById("send-button");
  const loadingMessage = document.getElementById("loadingMessage");
  const selectedFileContainer = document.getElementById(
    "selected-file-container"
  );
  const selectedFileName = document.getElementById("selected-file-name");
  const removeFileButton = document.getElementById("remove-file");

  let isInitialized = false;

  // open chatbot window
  function openChat() {
    chatWindow.classList.remove("hidden");

    // add welcome message
    if (!isInitialized) {
      chatMessages.innerHTML = "";
      addBotMessage(
        "👋 Upload a PDF file with the security report, and I will analyze it for you and help you resolve the issues."
      );
      isInitialized = true;
    }
  }

  // close chatbot window
  closeChat.addEventListener("click", function () {
    chatWindow.classList.add("hidden");
  });

  document.querySelectorAll(".open-chat").forEach((element) => {
    element.addEventListener("click", function (event) {
      event.preventDefault();
      openChat();
    });
  });

  // bot messages formated as HTML
  function addBotMessage(message) {
    const messageElement = document.createElement("div");
    messageElement.className = "message bot-message";

    messageElement.innerHTML = message;

    chatMessages.appendChild(messageElement);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  // add user message
  function addUserMessage(message) {
    const messageElement = document.createElement("div");
    messageElement.className = "message user-message";
    messageElement.textContent = message;
    chatMessages.appendChild(messageElement);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  // file upload
  fileInput.addEventListener("change", function () {
    if (fileInput.files.length > 0) {
      selectedFileName.textContent = fileInput.files[0].name;
      selectedFileContainer.classList.add("active");
      sendButton.disabled = false;
    }
  });

  // remove uploaded file
  removeFileButton.addEventListener("click", function (e) {
    e.stopPropagation();
    fileInput.value = "";
    selectedFileContainer.classList.remove("active");
    sendButton.disabled = true;
  });

  // send file to server
  sendButton.addEventListener("click", async function () {
    if (fileInput.files.length === 0) {
      return;
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    addUserMessage(`File uploaded: ${fileInput.files[0].name}`);

    // loading animation
    loadingMessage.classList.remove("hidden");

    // fetch request from OpenAI API
    try {
      // const response = await fetch("http://localhost:5200/api/upload-pdf", {
      const response = await fetch("https://web-vulnerability-scanner.onrender.com/api/upload-pdf", {
        method: "POST",
        body: formData,
      });

      const data = await response.json();
      loadingMessage.classList.add("hidden");

      if (data.success) {
        addBotMessage(data.analysis);
      } else {
        addBotMessage(
          `An error occurred: ${
            data.error || "The file could not be analyzed."
          }`
        );
      }
    } catch (error) {
      loadingMessage.classList.add("hidden");
      addBotMessage(`Could not connect to the server: ${error.message}`);
    }

    // reset upload form
    fileInput.value = "";
    selectedFileContainer.classList.remove("active");
    sendButton.disabled = true;

    chatMessages.scrollTop = chatMessages.scrollHeight;
  });

  // initialize chatbot
  if (!chatWindow.classList.contains("hidden")) {
    if (!isInitialized) {
      chatMessages.innerHTML = "";
      addBotMessage(
        "👋 Upload a PDF file with the security report, and I will analyze it for you and help you resolve the issues."
      );
      isInitialized = true;
    }
  }
});
