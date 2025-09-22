// static/js/results.js

document.addEventListener('DOMContentLoaded', () => {
    const percentage = (score / totalQuestions) * 100;
    const circle = document.querySelector('.circle');
    
    // Set the stroke-dasharray to animate the circle
    circle.style.strokeDasharray = `${percentage}, 100`;
});