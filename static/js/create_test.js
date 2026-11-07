document.addEventListener('DOMContentLoaded', () => {
    const questionsContainer = document.getElementById('questions-container');
    const addMcqBtn = document.getElementById('add-mcq-btn');
    const addOpenEndedBtn = document.getElementById('add-open-ended-btn');
    const createTestForm = document.getElementById('create-test-form');
    const saveTestBtn = document.getElementById('save-test-btn');
    const emptyQuestions = document.getElementById('empty-questions');

    if (!questionsContainer || !addMcqBtn || !addOpenEndedBtn || !createTestForm) {
        console.error('Create Test form elements could not be found.');
        return;
    }

    let questionCount = 0;

    // Update the empty state and question numbering.
    function updateQuestionsDisplay() {
        const cards = questionsContainer.querySelectorAll('.question-card');

        if (emptyQuestions) {
            emptyQuestions.style.display = cards.length === 0 ? 'block' : 'none';
        }

        cards.forEach((card, index) => {
            const type = card.dataset.questionType === 'mcq'
                ? 'Multiple Choice'
                : 'Open-Ended';

            const heading = card.querySelector('.question-title');

            if (heading) {
                heading.textContent = `Question ${index + 1} (${type})`;
            }
        });

        questionCount = cards.length;
    }

    // Create a Multiple Choice Question.
    function createMcqQuestion() {
        questionCount++;

        const questionHtml = `
            <div class="question-card form-card" data-question-type="mcq">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <span class="question-title fw-bold text-primary">
                        Question ${questionCount} (Multiple Choice)
                    </span>

                    <button type="button"
                            class="btn btn-sm btn-outline-danger remove-question-btn"
                            aria-label="Remove question">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>

                <div class="mb-3">
                    <label class="form-label">Question Text *</label>
                    <textarea class="form-control question-text"
                              rows="3"
                              placeholder="Enter your question..."
                              required></textarea>
                </div>

                <div class="options-container mb-3">
                    <label class="form-label">Answer Options *</label>

                    ${['A', 'B', 'C', 'D'].map(letter => `
                        <div class="input-group mb-2">
                            <span class="input-group-text">${letter}</span>
                            <input type="text"
                                   class="form-control option-input"
                                   placeholder="Enter option ${letter}"
                                   required>
                        </div>
                    `).join('')}
                </div>

                <div class="mb-2">
                    <label class="form-label">Correct Option *</label>
                    <select class="form-select correct-option" required>
                        <option value="">Select correct answer</option>
                        <option value="A">Option A</option>
                        <option value="B">Option B</option>
                        <option value="C">Option C</option>
                        <option value="D">Option D</option>
                    </select>
                </div>
            </div>
        `;

        questionsContainer.insertAdjacentHTML('beforeend', questionHtml);
        updateQuestionsDisplay();
    }

    // Create an Open-Ended Question.
    function createOpenEndedQuestion() {
        questionCount++;

        const questionHtml = `
            <div class="question-card form-card" data-question-type="open-ended">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <span class="question-title fw-bold text-primary">
                        Question ${questionCount} (Open-Ended)
                    </span>

                    <button type="button"
                            class="btn btn-sm btn-outline-danger remove-question-btn"
                            aria-label="Remove question">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>

                <div class="mb-3">
                    <label class="form-label">Question Text *</label>
                    <textarea class="form-control question-text"
                              rows="3"
                              placeholder="Enter your question..."
                              required></textarea>
                </div>

                <div class="mb-2">
                    <label class="form-label">Expected Answer / Keywords</label>
                    <textarea class="form-control ai-keywords"
                              rows="2"
                              placeholder="Enter expected answer or comma-separated keywords"></textarea>

                    <small class="text-muted">
                        These keywords can help evaluate written answers.
                    </small>
                </div>
            </div>
        `;

        questionsContainer.insertAdjacentHTML('beforeend', questionHtml);
        updateQuestionsDisplay();
    }

    // Add question buttons.
    addMcqBtn.addEventListener('click', createMcqQuestion);
    addOpenEndedBtn.addEventListener('click', createOpenEndedQuestion);

    // Remove question functionality.
    questionsContainer.addEventListener('click', (event) => {
        const removeButton = event.target.closest('.remove-question-btn');

        if (!removeButton) return;

        const questionCard = removeButton.closest('.question-card');

        if (questionCard) {
            questionCard.remove();
            updateQuestionsDisplay();
        }
    });

    // Collect all form information.
    function collectTestData() {
        const questionsData = [];
        const questionCards = questionsContainer.querySelectorAll('.question-card');

        questionCards.forEach((card, index) => {
            const questionText = card.querySelector('.question-text').value.trim();
            const isMcq = card.dataset.questionType === 'mcq';

            const question = {
                question_text: questionText,
                is_open_ended: !isMcq
            };

            if (isMcq) {
                const optionInputs = card.querySelectorAll('.option-input');
                const options = {};

                optionInputs.forEach((input, optionIndex) => {
                    options[String.fromCharCode(65 + optionIndex)] = input.value.trim();
                });

                question.options = options;
                question.correct_option = card.querySelector('.correct-option').value;
            } else {
                question.correct_answer_text =
                    card.querySelector('.ai-keywords').value.trim();
            }

            questionsData.push(question);
        });

        return questionsData;
    }

    // Submit the test.
    createTestForm.addEventListener('submit', async (event) => {
        event.preventDefault();

        if (!createTestForm.reportValidity()) {
            return;
        }

        const questions = collectTestData();

        if (questions.length === 0) {
            alert('Please add at least one question before saving.');
            return;
        }

        const invalidMcq = questions.some(question =>
            !question.is_open_ended &&
            !['A', 'B', 'C', 'D'].includes(question.correct_option)
        );

        if (invalidMcq) {
            alert('Please select a valid correct option for every multiple-choice question.');
            return;
        }

        const payload = {
            test_title: document.getElementById('test_title').value.trim(),
            topic: document.getElementById('topic').value.trim(),
            difficulty: document.getElementById('difficulty').value,
            time_limit_minutes: Number(
                document.getElementById('time_limit_minutes').value
            ),
            questions: questions
        };

        if (!payload.test_title || !payload.topic) {
            alert('Please enter a test title and subject/topic.');
            return;
        }

        if (!Number.isInteger(payload.time_limit_minutes) ||
            payload.time_limit_minutes < 1 ||
            payload.time_limit_minutes > 300) {
            alert('Please enter a time limit between 1 and 300 minutes.');
            return;
        }

        try {
            saveTestBtn.disabled = true;
            saveTestBtn.innerHTML =
                '<i class="fas fa-spinner fa-spin me-2"></i> Saving Test...';

            const csrfInput = createTestForm.querySelector(
                'input[name="csrf_token"]'
            );

            const headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            };

            if (csrfInput) {
                headers['X-CSRFToken'] = csrfInput.value;
            }

            const response = await fetch(createTestForm.action, {
                method: 'POST',
                headers: headers,
                body: JSON.stringify(payload)
            });

            const contentType = response.headers.get('content-type') || '';

            if (!contentType.includes('application/json')) {
                throw new Error(
                    'The server returned an unexpected response. Please check your Flask route.'
                );
            }

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || result.message || 'Unable to save the test.');
            }

            alert(result.message || 'Test created successfully!');

            window.location.href = creatorDashboardUrl;

        } catch (error) {
            console.error('Test creation error:', error);
            alert(error.message || 'An unexpected error occurred while saving the test.');

        } finally {
            saveTestBtn.disabled = false;
            saveTestBtn.innerHTML =
                '<i class="fas fa-floppy-disk me-2"></i> Save Test';
        }
    });

    updateQuestionsDisplay();
});