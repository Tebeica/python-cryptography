----------------------------------------
- Name: Teodor Tebeica                 -
- UCID: 30046038                       -
- CPSC418 Assignment 2                 -
- Question 9                           -
----------------------------------------


The security of the random number generator used:
    I used the 'secrets' library for python. The random number generator
provided by the Python random module is not cryptographically secure.
The secrets library has been developed to be "suitable for managing data 
such as passwords, account authentication, security tokens, and related
secrets". (https://docs.python.org/3/library/secrets.html)

Generating prime N:
    Use secrets library to generate a prime number of 511 bits then sympy
to check if that number is prime, assigns N to be 2q + 1, checks if that 
is prime as well, if not, recompute q.

Generating primitive root g:
    Generate a random 511 bit number in range N-1, use Fermat's little
theorem applied as an algorithm to check if it is a primitive root of N.

FILES:
    'server.py': creates a socket connection over an address and port, 
awaits for a client to attempt connection. Upon connecting, server sends
a 511 bit prime number N and a primitive root of N, called g to the client.
Receives from the client his/her username, a generated 16 byte salt and ac
variable v = g^x (mod N). After this registration phase, the secret 
negotiation/protocol can begin.

    'client.py': takes user input for his/her username and password, 
generates a 16 byte salt, and attepmts to connect to the Server. When 
connected succesfully, receive N and g from the Server, computes v and sends
over username, salt and v securely to the Server for storage. After this 
registration phase, the secret negotiation/protocol can begin.


    Disclaimer: everything should be implemented properly and as far as I 
am aware, there are no bugs present.