// static/js/take_test.js

document.addEventListener('DOMContentLoaded', () => {
    const submitButton = document.getElementById('submit-test-btn');
    const testId = document.getElementById('test-id').value;
    const questionsContainer = document.getElementById('test-form-container');

    submitButton.addEventListener('click', async () => {
        const answers = {};
        const questionBlocks = questionsContainer.querySelectorAll('.question-block');
        
        questionBlocks.forEach(block => {
            const questionId = block.dataset.questionId;
            const openEndedTextarea = block.querySelector('textarea');
            const mcqOption = block.querySelector('input[type="radio"]:checked');

            if (openEndedTextarea) {
                answers[questionId] = openEndedTextarea.value;
            } else if (mcqOption) {
                answers[questionId] = mcqOption.value;
            }
        });

        try {
            const response = await fetch(`/submit_test/${testId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ answers: answers })
            });

            const result = await response.json();

            if (response.ok) {
                // Redirect the user to the URL provided by the backend
                window.location.href = result.redirect_url;
            } else {
                alert(`Error: ${result.message}`);
            }

        } catch (error) {
            console.error('Submission failed:', error);
            alert('Failed to submit test. Please try again.');
        }
    });
});