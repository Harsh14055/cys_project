document.getElementById("scanBtn").addEventListener("click", scanFile);

let malwareCount = 0;
let benignCount = 0;
let unknownCount = 0;

let chart;

function createChart(){

const ctx=document.getElementById("statsChart");

chart=new Chart(ctx,{
type:"doughnut",

data:{
labels:["Malicious","Benign","Unknown"],

datasets:[{
data:[0,0,0],

backgroundColor:[
"#ef4444",
"#22c55e",
"#eab308"
]
}]
}
});
}

createChart();

function updateChart(){

chart.data.datasets[0].data=[
malwareCount,
benignCount,
unknownCount
];

chart.update();
}


document.getElementById("themeToggle").addEventListener("change",function(){

document.body.classList.toggle("dark");

});


async function scanFile(){

let fileInput=document.getElementById("fileInput");
let file=fileInput.files[0];

if(!file){
alert("Upload a file");
return;
}

let logs=document.getElementById("logs");
logs.innerHTML="<li>Uploading file...</li>";

let formData=new FormData();
formData.append("file",file);

let response=await fetch("/scan-file",{
method:"POST",
body:formData
});

let data=await response.json();

document.getElementById("fileName").innerText=data.file_name;
document.getElementById("md5").innerText=data.md5;
document.getElementById("sha256").innerText=data.sha256;

let statusBox=document.getElementById("statusBox");

statusBox.className="status-box";
statusBox.innerText=data.status;

if(data.status==="Malicious"){
statusBox.classList.add("malicious");
malwareCount++;
}

else if(data.status==="Benign"){
statusBox.classList.add("benign");
benignCount++;
}

else{
statusBox.classList.add("unknown");
unknownCount++;
}

updateChart();

logs.innerHTML="";

data.logs.forEach(log=>{
let li=document.createElement("li");
li.innerText=log;
logs.appendChild(li);
});

addHistory(data.file_name,data.status);

fileInput.value="";
}

function addHistory(file,status){

let table=document.getElementById("historyTable");

let row=document.createElement("tr");

row.innerHTML=`
<td>${file}</td>
<td>${status}</td>
`;

table.prepend(row);

}