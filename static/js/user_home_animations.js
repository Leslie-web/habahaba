// gsap.fromTo('.soma', {x: -500, opacity: 0}, {x: 0, opacity: 1})
// gsap.from('.soma', {x: -500, duration: 1, opacity: 1})
// gsap.from('.ukulima', {x: -500, duration: 1, opacity: 1, delay: 0.1})
// gsap.from('.household', {x: -500, duration: 1, opacity: 1, delay: 0.2})
// gsap.from('.medical', {x: -500, duration: 1, opacity: 1, delay: 0.3})

gsap.fromTo('.soma',
    {x: -500, opacity: 0},
    {x: 0, opacity: 1, duration: 1})
gsap.fromTo('.ukulima',
    {x: -500, opacity: 0},
    {x: 0, opacity: 1, duration: 1, delay: 0.1})
gsap.fromTo('.household',
    {x: -500, opacity: 0},
    {x: 0, opacity: 1, duration: 1, delay: 0.2})
gsap.fromTo('.medical',
    {x: -500, opacity: 0},
    {x: 0, opacity: 1, duration: 1, delay: 0.3})