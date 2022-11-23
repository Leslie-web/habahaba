var config;

 function drawChart(chart,bartype,chartArea,data, labels, colors, title, destroy) {
        config = {
            type: bartype,
            responsive: false,
            data: {
                datasets: [{
                    fill:false,
                    label: title,
                    data: data,
                    backgroundColor: dynamicColors()
                }],
                labels: labels,
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                legend: {
                    position: 'top',
                },
                /*title: {
                    display: true,
                    text: title
                },*/
                animation: {
                    animateScale: true,
                    animateRotate: true
                }
            }
        };
        if (chart != null && destroy) {
            chart.destroy();
        }
        
        var ctx = document.getElementById(chartArea).getContext("2d");
        ctx.height = 200;
        chart = new Chart(ctx, config);
        return chart;
    }

    function dynamicColors() {
        var r = Math.floor(Math.random() * 255);
        var g = Math.floor(Math.random() * 255);
        var b = Math.floor(Math.random() * 255);
        return "rgb(" + r + "," + g + "," + b + ")";
    }