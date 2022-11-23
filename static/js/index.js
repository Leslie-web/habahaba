(function() {
    if('serviceWorker' in navigator) {
      window.addEventListener('load', () => {
        navigator.serviceWorker.register('service-worker.js')
                 .then(function(registration) {
                 console.log('Service Worker Registered');
                 return registration;
        })
        .catch(function(err) {
          console.error('Unable to register service worker.', err);
        });
        navigator.serviceWorker.ready.then(function(registration) {
          console.log('Service Worker Ready');
        });
      });
    }
  })();
  
  let deferredPrompt;
  const btnAdd = document.querySelector('#btn-add');
  
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    btnAdd.style.visibility = 'visible';
    // e.showInstallPromotion();
    console.log('beforeinstallprompt event fired');
  });
  
  btnAdd.addEventListener('click', async(e) => {
    // e.hideInstallPromotion();
    btnAdd.style.visibility = 'hidden';
    deferredPrompt.prompt();
    deferredPrompt.userChoice
      .then((choiceResult) => {
        if (choiceResult.outcome === 'accepted') {
          console.log('User accepted the A2HS prompt');
        } else {
          console.log('User dismissed the A2HS prompt');
        }
      });
    const { outcome } = await deferredPrompt.userChoice;
    console.log(`User response to the install prompt: ${outcome}`);
    deferredPrompt = null;
  });
  
  window.addEventListener('appinstalled', () => {

    hideInstallPromotion();

    deferredPrompt = null;

    app.logEvent('app', 'installed');

    console.log('PWA succesfully installed');
  });

  document.querySelector("#scanButton").onclick = async () => {
    if ('NDEFReader' in window) {
      const ndef = new NDEFReader();
  
      ndef.scan().then(() => {
        console.log("Scan started successfully.");
        ndef.onreadingerror = () => {
          console.log("Cannot read data from the NFC tag. Try another one?");
        };
        ndef.onreading = event => {
          const message = event.message;
          for (const record of message.records) {
            console.log(message.records[0].data.buffer);
            var data = new Uint8Array(message.records[0].data.buffer);
            var str ="";
            data.forEach(element => {
              str +=String.fromCharCode(element) 
            });
            var json = JSON.parse(str);

            var userData = "Reg No. " + json.reg + " NfcID: " + json.nfcid;
            alert(userData);
            document.getElementById("RegNo").value = json.reg;
            document.getElementById("nfcid").value = json.nfcid;
          }
        };
      }).catch(error => {
        console.log(`Error! Scan failed to start: ${error}.`);
      });
    }
    else {
      console.log('Device does not support NFC!!')
    }

    // ndef.write(
    //   "Hello World"
    // ).then(() => {
    //   console.log("Message written.");
    // }).catch(error => {
    //   console.log(`Write failed :-( try again: ${error}.`);
    // });
  };

const getFileBtn = document.getElementById("fs-get")

getFileBtn.onclick = async () => {
  const [handle] = await window.showOpenFilePicker();
  const file = await handle.getFile();
  console.log(file);
}