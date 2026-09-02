const input=document.getElementById("fileInput");

const nameBox=document.getElementById("fileName");

const sizeBox=document.getElementById("fileSize");

const progress=document.getElementById("progressBar");

input.addEventListener("change",()=>{

const file=input.files[0];

if(!file) return;

nameBox.innerHTML=file.name;

sizeBox.innerHTML=(file.size/1024/1024).toFixed(2)+" MB";

let width=0;

const timer=setInterval(()=>{

width+=2;

progress.style.width=width+"%";

if(width>=100){

clearInterval(timer);

}

},20);

});