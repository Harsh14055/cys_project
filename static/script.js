document.getElementById("scanBtn").addEventListener("click", function(e){
e.preventDefault();
scanFile();
});


async function scanFile(){

console.log("Scan started");

let fileInput = document.getElementById("fileInput");
let file = fileInput.files[0];

if(!file){
alert("Please upload a file");
return;
}

let formData = new FormData();
formData.append("file", file);

let response = await fetch("/scan-file",{
method:"POST",
body:formData
});

let data = await response.json();

console.log("Result received", data);

document.getElementById("fileName").innerText = data.file_name;
document.getElementById("md5").innerText = data.md5;
document.getElementById("sha256").innerText = data.sha256;

let statusElement = document.getElementById("status");
statusElement.innerText = data.status;

if(data.status === "Malicious")
statusElement.className = "badge bg-danger";

else if(data.status === "Benign")
statusElement.className = "badge bg-success";

else
statusElement.className = "badge bg-warning";

let logs = document.getElementById("logs");
logs.innerHTML = "";

data.logs.forEach(log=>{
let li = document.createElement("li");
li.innerText = log;
logs.appendChild(li);
});

fileInput.value = "";

}