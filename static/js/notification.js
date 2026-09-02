// ==========================================
// Notification System
// ==========================================

let notificationCount = 0;

// Increase notification badge
function addNotification(message){

    notificationCount++;

    const badge = document.getElementById("notificationCount");

    if(badge){

        badge.innerHTML = notificationCount;

    }

    console.log(message);

}

// Reset badge
function clearNotifications(){

    notificationCount = 0;

    const badge = document.getElementById("notificationCount");

    if(badge){

        badge.innerHTML = "0";

    }

}

// Show threat notification
function threatDetected(fileName,risk){

    addNotification(

        "Threat Detected : " + fileName

    );

    const text =

`🚨 Threat Detected

File : ${fileName}

Risk : ${risk}`;

    alert(text);

}

// Safe notification
function safeFile(fileName){

    console.log(

        fileName + " is Safe."

    );

}

// Update badge after scan result
function processScan(result){

    if(!result) return;

    if(result.prediction === "Safe"){

        safeFile(result.filename);

    }

    else{

        threatDetected(

            result.filename,

            result.risk

        );

    }

}

// Initialize
document.addEventListener("DOMContentLoaded",function(){

    const badge = document.getElementById("notificationCount");

    if(badge){

        badge.innerHTML = notificationCount;

    }

});