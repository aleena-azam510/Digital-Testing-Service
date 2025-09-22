// static/js/create_test.js

document.addEventListener('DOMContentLoaded', () => {
    const questionsContainer = document.getElementById('questions-container');
    const addMcqBtn = document.getElementById('add-mcq-btn');
    const addOpenEndedBtn = document.getElementById('add-open-ended-btn');
    const createTestForm = document.getElementById('create-test-form');

    let questionCount = 0;

    const createMcqQuestion = () => {
        questionCount++;
        const questionHtml = `
            <div class="card my-3 question-card" data-question-type="mcq">
                <div class="card-header bg-primary text-white d-flex justify-content-between">
                    <span>Question ${questionCount} (Multiple Choice)</span>
                    <button type="button" class="btn-close btn-close-white remove-question-btn"></button>
                </div>
                <div class="card-body">
                    <div class="mb-3">
                        <label class="form-label">Question Text</label>
                        <textarea class="form-control question-text" rows="3" required></textarea>
                    </div>
                    <div class="options-container">
                        <label class="form-label">Options</label>
                        <div class="input-group mb-2">
                            <span class="input-group-text">A</span>
                            <input type="text" class="form-control option-input" required>
                        </div>
                        <div class="input-group mb-2">
                            <span class="input-group-text">B</span>
                            <input type="text" class="form-control option-input" required>
                        </div>
                        <div class="input-group mb-2">
                            <span class="input-group-text">C</span>
                            <input type="text" class="form-control option-input" required>
                        </div>
                        <div class="input-group mb-2">
                            <span class="input-group-text">D</span>
                            <input type="text" class="form-control option-input" required>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Correct Option (e.g., A, B, C, D)</label>
                        <input type="text" class="form-control correct-option" required>
                    </div>
                </div>
            </div>
        `;
        questionsContainer.insertAdjacentHTML('beforeend', questionHtml);
    };

    const createOpenEndedQuestion = () => {
        questionCount++;
        const questionHtml = `
            <div class="card my-3 question-card" data-question-type="open-ended">
                <div class="card-header bg-warning text-dark d-flex justify-content-between">
                    <span>Question ${questionCount} (Open-Ended)</span>
                    <button type="button" class="btn-close remove-question-btn"></button>
                </div>
                <div class="card-body">
                    <div class="mb-3">
                        <label class="form-label">Question Text</label>
                        <textarea class="form-control question-text" rows="3" required></textarea>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">AI Analysis Keywords (Comma-separated)</label>
                        <input type="text" class="form-control ai-keywords" placeholder="e.g., correct, accurate, valid">
                    </div>
                </div>
            </div>
        `;
        questionsContainer.insertAdjacentHTML('beforeend', questionHtml);
    };

    addMcqBtn.addEventListener('click', createMcqQuestion);
    addOpenEndedBtn.addEventListener('click', createOpenEndedQuestion);

    // Remove question button functionality
    questionsContainer.addEventListener('click', (e) => {
        if (e.target.classList.contains('remove-question-btn')) {
            e.target.closest('.question-card').remove();
            // Re-number questions
            questionsContainer.querySelectorAll('.question-card .card-header span').forEach((el, index) => {
                const type = el.closest('.question-card').dataset.questionType === 'mcq' ? 'Multiple Choice' : 'Open-Ended';
                el.textContent = `Question ${index + 1} (${type})`;
            });
            questionCount--;
        }
    });

    // Form submission handler
    createTestForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const testTitle = document.getElementById('test_title').value;
        const questionsData = [];
        const questionCards = questionsContainer.querySelectorAll('.question-card');

        questionCards.forEach(card => {
            const questionText = card.querySelector('.question-text').value;
            const isMcq = card.dataset.questionType === 'mcq';

            let qData = {
                question_text: questionText,
                is_open_ended: !isMcq
            };

            if (isMcq) {
                const options = {};
                const optionInputs = card.querySelectorAll('.option-input');
                optionInputs.forEach((input, index) => {
                    const optionKey = String.fromCharCode(65 + index); // A, B, C, D
                    options[optionKey] = input.value;
                });
                qData.options = options;
                qData.correct_option = card.querySelector('.correct-option').value.toUpperCase();
            } else {
                qData.correct_answer_text = card.querySelector('.ai-keywords').value;
            }
            questionsData.push(qData);
        });

        // Create a single JSON object with all the data
        const payload = {
            test_title: testTitle,
            questions: questionsData
        };

        // Send the JSON payload to the Flask route
        const response = await fetch(createTestForm.action, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        const result = await response.json();

        if (response.ok) {
            alert(result.message);
            // Use the variable that was set in the HTML template
            window.location.href = creatorDashboardUrl; 
        } else {
            alert(result.error);
        }
    });
});