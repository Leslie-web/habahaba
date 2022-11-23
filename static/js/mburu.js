var config;

 function drawChart(bartype,chartArea,barChartData,title, destroy,isStacked=false) { 
        if(isStacked){
            config = {
                type: bartype,
                responsive: false, 
                data: barChartData,
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    legend: {
                        position: 'top',
                    }, 
                    title: {
                        display: true,
                        text: title
                    },
                    animation: {
                        animateScale: true,
                        animateRotate: true
                    },
                    scales: {
                        xAxes: [{
                            stacked: isStacked,
                        }],
                        yAxes: [{
                            stacked: isStacked
                        }]
                    }
                }
            };
        } else {
            config = {
                type: bartype,
                responsive: false, 
                data: barChartData,
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    legend: {
                        position: 'top',
                    }, 
                    title: {
                        display: true,
                        text: title
                    },
                    animation: {
                        animateScale: true,
                        animateRotate: true
                    }, 
                }
            };
        }

        
        var ctx = document.getElementById(chartArea).getContext("2d");
        ctx.height = 200;
        var chart = new Chart(ctx, config);
        return chart;
    }

    function dynamicColors() {
        var r = Math.floor(Math.random() * 255);
        var g = Math.floor(Math.random() * 255);
        var b = Math.floor(Math.random() * 255);
        return "rgb(" + r + "," + g + "," + b + ")";
    }