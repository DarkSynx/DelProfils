# DelProfils

**DelProfils** est un utilitaire natif pour Windows, écrit en C++20, destiné à inventorier et supprimer les profils utilisateurs locaux inactifs. Il propose des filtres par nom avec jokers et protège les profils spéciaux ainsi que les profils actuellement chargés.

Le dépôt contient les sources, les tests C++ et le projet Red Panda C++. Aucun exécutable compilé n’est inclus.

## Fonctionnalités

- Inventaire des profils éligibles avant suppression.
- Filtres d’inclusion et d’exclusion par nom, avec `*` et `?`.
- Mode silencieux avec `/q`.
- Protection des profils système/spéciaux et des profils chargés.
- Refus de la suppression distante : une cible distante ne peut pas être supprimée par cette version.
- Prise en charge du nom de la machine locale avec `/c:`.

## Exemple d’utilisation en GPO

```bat
DelProfils1.exe /q /ed:admin*
```

Cette commande supprime silencieusement les profils locaux inactifs éligibles, sauf ceux dont le nom correspond au motif `admin*`.

**Attention :** sans filtre d’âge comme `/d:<jours>`, tous les profils inactifs éligibles peuvent être concernés. `/q` supprime les messages et les demandes de confirmation ; testez d’abord la sélection en mode inventaire/liste.

## Utilisation prudente

1. Lancez d’abord l’outil en mode inventaire/liste pour vérifier les profils ciblés.
2. Vérifiez les filtres, notamment les jokers et les exclusions.
3. Testez la commande sur une machine virtuelle et des comptes temporaires.
4. Déployez-la ensuite avec les droits nécessaires et une GPO maîtrisée.

DelProfils supprime des profils utilisateurs. Une erreur de filtre peut entraîner la suppression de profils non souhaités. L’administrateur qui déploie l’outil doit valider la commande et la population ciblée avant toute exécution silencieuse.

## Compilation sous Windows

1. Installer Red Panda C++ avec MinGW-w64 x64 et la prise en charge de C++20.
2. Ouvrir `DelProfils1.dev`.
3. Effectuer **Clean**, puis **Build**.
4. Vérifier le résultat et les éventuelles erreurs dans la console de l’IDE.

Le fichier `makefile.win` documente les options de compilation : C++20, Unicode, cible Windows 10 ou ultérieure et bibliothèques système nécessaires.

## Tests et validation

Le dossier `tests/` contient les tests unitaires C++. Les tests destructifs doivent être exécutés dans une machine virtuelle et limités à des comptes temporaires.

La validation d’intégration GPO R7 a été réalisée dans une VM sur l’exécutable testé séparément : **42 tests réussis sur 42**, dont l’exécution de la commande exacte `/q /ed:admin*`. Ce résultat valide cet exécutable dans cet environnement ; il ne garantit pas qu’une recompilation de ces sources donnera le même binaire sans nouvelle vérification.

## Arborescence

- `main.cpp`, `src/` : code de l’application.
- `tests/` : tests unitaires C++.
- `DelProfils1.dev`, `makefile.win` : configuration du projet et de la compilation.
- `DelProfils1_private.rc`, `DelProfils1_private.h`, `app.ico` : ressources de l’application.

## Licence

Licence prévue : MIT. Ajoute le fichier `LICENSE` MIT au dépôt lors de sa création.
