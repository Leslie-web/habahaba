// if ('serviceWorker' in navigator) {
//     navigator.serviceWorker.register('/sw.js')
//         .then((reg) => console.log('Service worker registered', reg))
//         .catch((err) => console.log('Not registered', err))
// }

// if ('serviceWorker' in navigator) {
//     window.addEventListener('load', function () {
//         navigator.serviceWorker.register('sw.js', {scope: '/'})
//             .then(function (reg) {
//                 console.log('ServiceWorker registered: ', reg.scope)
//             }, function (err) {
//                 console.log('ServiceWorker registration failed', err);
//             });
//     });
// }