chrome.runtime.onInstalled.addListener(() => {
  console.log("Extension Installed");
});

// Function to check URLs with VirusTotal API
async function checkURLWithVirusTotal(url) {
  const apiKey = '2e6b020210a78be435d443ea630e26702e7d6a37a3654ba2cb9dfd2df65c38d9';
  const apiUrl = `https://www.virustotal.com/vtapi/v2/url/report?apikey=${apiKey}&resource=${encodeURIComponent(url)}`;

  try {
    const response = await fetch(apiUrl);
    const data = await response.json();
    if (data.positives > 0) {
      console.log(`URL ${url} is malicious.`);
      chrome.notifications.create({
        title: 'Malicious Website Blocked',
        message: `The website ${url} was blocked for being unsafe.`,
        // iconUrl: 'icons/icon128.png',
        type: 'basic'
      });
      return false;
    }
  } catch (error) {
    console.error('Error checking URL:', error);
  }
  return true;
}

  // Blocking all HTTP sites (enforcing HTTPS everywhere)
  chrome.declarativeNetRequest.updateDynamicRules({
    addRules: [
      {
        id: 1,
        priority: 1,
        action: { type: 'redirect', redirect: { transform: { scheme: "https" } } },
        condition: {
          urlFilter: "http://*",
          resourceTypes: ["main_frame"]
        }
      }
    ],
    removeRuleIds: [1]
  });



// Blocking suspicious URLs
// chrome.declarativeNetRequest.updateDynamicRules({
//   addRules: [{
//     id: 1,
//     priority: 1,
//     action: { type: 'block' },
//     condition: {
//       urlFilter: "http://*",
//       resourceTypes: ["main_frame"]
//     }
//   }]
// });
