// static/js/main.js

document.addEventListener('DOMContentLoaded', () => {
    // This is where you would put your custom JavaScript.
    // For example, to handle the test submission with an AJAX call.

    // Example of a simple AJAX call for a test submission form
    const testForm = document.getElementById('test-form');
    if (testForm) {
        testForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const testId = testForm.dataset.testid;
            const answers = {};
            testForm.querySelectorAll('input[name^="answer_"], textarea[name^="answer_"]').forEach(input => {
                const questionId = input.name.split('_')[1];
                answers[questionId] = input.value;
            });

            const response = await fetch(`/submit_test/${testId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ answers })
            });

            const result = await response.json();

            if (response.ok) {
                alert(`Test Submitted!\nYour Score: ${result.score}\nAI Feedback: ${JSON.stringify(result.feedback, null, 2)}`);
                window.location.href = '/dashboard';
            } else {
                alert('Error submitting test: ' + result.message);
            }
        });
    }
});