
#ifndef INJECT_HTML_H
#define INJECT_HTML_H

// floating chatbot UI

#define INJECT_HTML \
  "\
<div id=\"floating-chatbot\" style=\"\
    position: fixed;\
    bottom: 20px;\
    right: 20px;\
    width: 300px;\
    height: 400px;\
    background: white;\
    border-radius: 10px;\
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);\
    display: flex;\
    flex-direction: column;\
    z-index: 2147483647;\
    font-family: Arial, sans-serif;\
    display: none;\
\">\
    <div id=\"chatbot-header\" style=\"\
        padding: 10px;\
        background: #007bff;\
        color: white;\
        border-radius: 10px 10px 0 0;\
        cursor: pointer;\
        display: flex;\
        justify-content: space-between;\
        align-items: center;\
    \">\
        <span>AI Assistant</span>\
        <button id=\"chatbot-close\" style=\"\
            background: none;\
            border: none;\
            color: white;\
            cursor: pointer;\
            font-size: 18px;\
        \">×</button>\
    </div>\
    <div id=\"chatbot-messages\" style=\"\
        flex-grow: 1;\
        overflow-y: auto;\
        padding: 10px;\
        display: flex;\
        flex-direction: column;\
        gap: 10px;\
    \">\
    </div>\
    <div id=\"chatbot-thinking\" style=\"\
        padding: 10px;\
        display: none;\
        color: #666;\
        font-style: italic;\
    \">AI is thinking...</div>\
    <div id=\"chatbot-input\" style=\"\
        padding: 10px;\
        border-top: 1px solid #eee;\
        display: flex;\
        gap: 10px;\
    \">\
        <input type=\"text\" id=\"chatbot-text\" placeholder=\"Type a message...\" style=\"\
            flex-grow: 1;\
            padding: 8px;\
            border: 1px solid #ddd;\
            border-radius: 5px;\
            outline: none;\
        \">\
        <button id=\"chatbot-send\" style=\"\
            background: #007bff;\
            color: white;\
            border: none;\
            padding: 8px 15px;\
            border-radius: 5px;\
            cursor: pointer;\
        \">Send</button>\
    </div>\
</div>\
<div id=\"chatbot-trigger\" style=\"\
    position: fixed;\
    bottom: 20px;\
    right: 20px;\
    width: 60px;\
    height: 60px;\
    background: #007bff;\
    border-radius: 50%;\
    display: flex;\
    align-items: center;\
    justify-content: center;\
    cursor: pointer;\
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);\
    z-index: 2147483647;\
\">\
    <svg width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"white\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\">\
        <path d=\"M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z\"></path>\
    </svg>\
</div>\
<script>(function(){\
  var chatbot=document.getElementById('floating-chatbot');\
  var trigger=document.getElementById('chatbot-trigger');\
  var closeBtn=document.getElementById('chatbot-close');\
  var messages=document.getElementById('chatbot-messages');\
  var input=document.getElementById('chatbot-text');\
  var sendBtn=document.getElementById('chatbot-send');\
  var thinking=document.getElementById('chatbot-thinking');\
  function toggle(){\
    if(chatbot.style.display==='none'){chatbot.style.display='flex';trigger.style.display='none';}\
    else{chatbot.style.display='none';trigger.style.display='flex';}\
  }\
  function addMessage(t,u){var d=document.createElement('div');\
    d.style.cssText='padding:8px 12px;border-radius:10px;max-width:80%;word-wrap:break-word;align-self:'+(u?'flex-end':'flex-start')+';background:'+(u?'#007bff':'#f0f0f0')+';color:'+(u?'white':'black');\
    d.textContent=t;messages.appendChild(d);messages.scrollTop=messages.scrollHeight;}\
  async function send(){var t=input.value.trim();if(!t)return;addMessage(t,true);input.value='';thinking.style.display='block';\
    try{addMessage('Hello from the injected badge! (local demo)');}catch(e){addMessage('Error.');}finally{thinking.style.display='none';}}\
  trigger.addEventListener('click',toggle);closeBtn.addEventListener('click',toggle);sendBtn.addEventListener('click',send);\
  input.addEventListener('keypress',function(e){if(e.key==='Enter')send();});\
})();</script>\
"

#endif
