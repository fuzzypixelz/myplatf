document.getElementById("start").addEventListener("click", function() {
    document.getElementById("guide").style.display = "none";
    document.getElementById("quiz").style.display = "block";
    startQuiz();
});

function startQuiz() {
    let currentQuestion = 0;
    let score = 1;
    let totalQuestions = MCQS.length;
    let timeLeft = 15; // Temps initial en secondes pour chaque question
    let timerId;

    function displayQuestion(questionIndex) {
        let q = MCQS[questionIndex];
        document.getElementById("questionText").textContent = q.question;
        document.getElementById("questionNo").textContent = "Question " + (questionIndex + 1);
        document.getElementById("option1").textContent = q.choice1;
        document.getElementById("option2").textContent = q.choice2;
        document.getElementById("option3").textContent = q.choice3;
        document.getElementById("option4").textContent = q.choice4;

        setupAnswerHandlers(q.answer);
    }

    function setupAnswerHandlers(correctAnswer) {
        let options = document.querySelectorAll(".choice_que");
        options.forEach((option, index) => {
            option.onclick = () => {
                if (index === correctAnswer) {
                    score++;
                }
                clearInterval(timerId); // Stop the timer before moving to next question or ending quiz
                if (currentQuestion < totalQuestions - 1) {
                    currentQuestion++;
                    displayQuestion(currentQuestion);
                } else {
                    showResult();
                }
            };
        });
    }

    function startTimer() {
        timeLeft = 15; // Reset time for the new question
        timerId = setInterval(() => {
            timeLeft--;
            document.getElementById("time").textContent = timeLeft;
            if (timeLeft <= 0) {
                clearInterval(timerId);
                if (currentQuestion < totalQuestions - 1) {
                    currentQuestion++;
                    displayQuestion(currentQuestion);
                } else {
                    showResult();
                }
            }
        }, 1000);
    }
    function showResult() {
        document.getElementById("quiz").style.display = "none";
        document.getElementById("result").style.display = "block";
        document.getElementById("points").textContent = "Votre score est de : " + score + " sur " + totalQuestions;
    
        document.getElementById("returnToEnergy").onclick = function() {
            window.location.href = "/energie.html"; // Assurez-vous que l'URL est correcte
            window.location.reload(true); // Ajout de la commande pour rafraîchir la page
        };
        
        document.getElementById("startAgain").onclick = function() {
            document.getElementById("result").style.display = "none";
            document.getElementById("guide").style.display = "block";
            startQuiz();
        };
    }
    
    displayQuestion(currentQuestion);
    startTimer();}    
