// ==========================================
// AI Security Chatbot
// ==========================================

const chatbotBtn = document.getElementById("chatbot-btn");
const chatbotBox = document.getElementById("chatbot-box");
const chatArea = document.getElementById("chat-area");
const userInput = document.getElementById("userMessage");

// ==========================================
// Toggle Chat Window
// ==========================================

if(chatbotBtn){

    chatbotBtn.addEventListener("click",function(){

        if(chatbotBox.style.display==="flex"){

            chatbotBox.style.display="none";

        }

        else{

            chatbotBox.style.display="flex";

            userInput.focus();

        }

    });

}

// ==========================================
// Send Message
// ==========================================

function sendMessage(){

    const message=userInput.value.trim();

    if(message==="") return;

    addUserMessage(message);

    userInput.value="";

    fetch("/chatbot",{

        method:"POST",

        headers:{

            "Content-Type":"application/json"

        },

        body:JSON.stringify({

            message:message

        })

    })

    .then(response=>response.json())

    .then(data=>{

        addBotMessage(data.reply);

    })

    .catch(()=>{

        addBotMessage(

            "⚠ Unable to contact AI Assistant."

        );

    });

}

// ==========================================
// User Message
// ==========================================

function addUserMessage(message){

    const div=document.createElement("div");

    div.className="user-msg";

    div.innerHTML=message;

    chatArea.appendChild(div);

    scrollChat();

}

// ==========================================
// Bot Message
// ==========================================

function addBotMessage(message){

    const div=document.createElement("div");

    div.className="bot-msg";

    div.innerHTML=message;

    chatArea.appendChild(div);

    scrollChat();

}

// ==========================================
// Scroll Bottom
// ==========================================

function scrollChat(){

    chatArea.scrollTop=chatArea.scrollHeight;

}

// ==========================================
// Enter Key
// ==========================================

if(userInput){

    userInput.addEventListener("keypress",function(e){

        if(e.key==="Enter"){

            e.preventDefault();

            sendMessage();

        }

    });

}

// ==========================================
// Welcome Message
// ==========================================

document.addEventListener("DOMContentLoaded",function(){

    if(chatArea){

        addBotMessage(

            "👋 Hello! I'm your AI Security Assistant.<br><br>" +

            "I can help you with:<br>" +

            "• Malware Detection<br>" +

            "• Threat Intelligence<br>" +

            "• File Scan Results<br>" +

            "• Network Security<br>" +

            "• AI Threat Analysis"

        );

    }

});

const chatToggle = document.getElementById("chat-toggle");
const chatWindow = document.getElementById("chat-window");
const closeChat = document.getElementById("close-chat");

if(chatToggle){
    chatToggle.onclick = function(){

        if(chatWindow.style.display==="flex"){

            chatWindow.style.display="none";

        }else{

            chatWindow.style.display="flex";

        }

    };
}

if(closeChat){
    closeChat.onclick=function(){

        chatWindow.style.display="none";

    };
}