Port Scanner em Python

Um scanner de portas TCP rápido e concorrente, desenvolvido em Python para fins de auditoria de redes e cibersegurança.
Como utilizar

Abre o terminal e escreve o comando indicando o alvo.

Para um único IP:
python scanner.py 127.0.0.1

Para um intervalo de IPs:
python scanner.py 192.168.1.1 192.168.1.5

Para uma rede inteira:
python scanner.py 10.0.0.0/24

Tecnologias

Multithreading (ThreadPoolExecutor)
Python 3
Sockets nativos
