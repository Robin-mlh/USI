### USI Lite
***USI allégé***

USI lite est une version de USI réduite au stricte minimum.

***Les messages ne sont pas chiffrés*** et certaines fonctionnalités y sont absentes.
En d'autres termes, n'importe qui étant capable d'intercepter la communication peut lire les messages échangés.
Le but est de réduire au maximum le poids du programme avec au total seulement 4 modules de la bibliothèque standard de Python.

Seul Python 3.6+ est requis.

Plus de problèmes peuvent survenir avec cette version, ***ne l'utiliser que si nécessaire.***

#### Utilisation

Lancer le script et répondre aux questions pour utiliser USI Lite.

    python3 ./usi-lite.py

L'un des utilisateurs devra lancer USI en mode serveur pour attendre les clients.
Pour recevoir des connexions hors du réseau local, penser à ouvrir le port utilisé (12800 par défaut) sur le routeur.
