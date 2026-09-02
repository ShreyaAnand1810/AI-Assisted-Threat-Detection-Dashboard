// ==========================================
// AI Threat Intelligence
// ==========================================

// Malware Feed
function loadMalware(){

    fetch("/api/malware_feed")

    .then(res=>res.json())

    .then(data=>{

        let html="";

        document.getElementById("malwareCount").innerHTML=data.length;

        data.forEach(item=>{

            html+=`

            <div class="feed-item">

                <div class="feed-title">

                    ${item.name}

                </div>

                <div>

                    ${item.description}

                </div>

                <div class="feed-date">

                    ${item.date}

                </div>

                <span class="feed-risk">

                    ${item.risk}

                </span>

            </div>

            `;

        });

        document.getElementById("malwareFeed").innerHTML=html;

    })

    .catch(()=>{

        document.getElementById("malwareFeed").innerHTML=

        "Unable to load malware feed.";

    });

}

// CVE Feed
function loadCVEs(){

    fetch("/api/cve_feed")

    .then(res=>res.json())

    .then(data=>{

        let html="";

        document.getElementById("cveCount").innerHTML=data.length;

        data.forEach(item=>{

            html+=`

            <div class="feed-item">

                <div class="feed-title">

                    ${item.cve}

                </div>

                <div>

                    ${item.summary}

                </div>

                <div class="feed-date">

                    Severity :

                    ${item.severity}

                </div>

            </div>

            `;

        });

        document.getElementById("cveFeed").innerHTML=html;

    })

    .catch(()=>{

        document.getElementById("cveFeed").innerHTML=

        "Unable to load CVEs.";

    });

}

// IOC Feed
function loadIOC(){

    fetch("/api/ioc_feed")

    .then(res=>res.json())

    .then(data=>{

        let html="";

        data.forEach(item=>{

            html+=`

            <div class="feed-item">

                <div class="feed-title">

                    ${item.type}

                </div>

                <div>

                    ${item.value}

                </div>

            </div>

            `;

        });

        document.getElementById("iocFeed").innerHTML=html;

    })

    .catch(()=>{

        document.getElementById("iocFeed").innerHTML=

        "Unable to load Indicators.";

    });

}

// AI Recommendation
function updateAISummary(){

    fetch("/api/ai_summary")

    .then(res=>res.json())

    .then(data=>{

        document.getElementById("riskLevel").innerHTML=data.risk;

        document.getElementById("aiSummary").innerHTML=`

        <div class="feed-item">

            <div class="feed-title">

                AI Recommendation

            </div>

            <div>

                ${data.summary}

            </div>

        </div>

        `;

    })

    .catch(()=>{

        document.getElementById("aiSummary").innerHTML=

        "Unable to generate recommendation.";

    });

}

// Load Everything
document.addEventListener("DOMContentLoaded",function(){

    console.log("Threat Intelligence Loaded");

    loadMalware();

    loadCVEs();

    loadIOC();

    updateAISummary();

});