# FutPulse — modèle de données du centre des matchs

## Règle d'architecture

Ne pas exécuter de SQL direct pour créer les tables FutPulse dans la base principale.

221Cloud gère les bases des applications avec :
- `customer_databases` pour la base logique ;
- `customer_database_tables` pour enregistrer chaque table ;
- `customer_database_columns` pour enregistrer les colonnes ;
- des tables physiques générées par le système ;
- `application_database_table_permissions` pour les droits de l'application publiée.

Toute création doit respecter ce registre, les identifiants de la base reliée à la publication et les permissions. Ne jamais créer une table globale `futpulse_*` hors de ce mécanisme.

## Tables logiques prévues

Chaque table possède au plus 50 colonnes personnalisées. Les types pris en charge par le gestionnaire actuel sont `text`, `number`, `boolean` et `date`. Les contrôles métier (statuts, scores positifs, équipes différentes, dates ISO, doublons de source) doivent donc être validés dans les routes serveur.

### 1. Compétitions
- `nom` (text), `slug` (text), `pays` (text), `region` (text)
- `type` (text : league, cup, international, other)
- `logo_url` (text), `actif` (boolean)
- `source_donnees` (text), `source_competition_id` (text)

### 2. Saisons
- `competition_id` (text), `nom` (text)
- `date_debut` (date), `date_fin` (date), `saison_courante` (boolean)

### 3. Équipes
- `nom` (text), `slug` (text), `nom_court` (text)
- `pays` (text), `logo_url` (text)
- `source_donnees` (text), `source_equipe_id` (text)

### 4. Matchs
- `competition_id`, `saison_id`, `equipe_domicile_id`, `equipe_exterieure_id` (text)
- `coup_envoi` (text ISO 8601 avec fuseau), `statut` (text)
- `score_domicile`, `score_exterieur` (number)
- `stade`, `journee`, `tour` (text)
- `source_donnees`, `source_match_id`, `source_url`, `source_maj`, `derniere_synchro` (text)

Statuts autorisés côté serveur : scheduled, live, halftime, finished, postponed, cancelled, suspended.

### 5. Classements
- `competition_id`, `saison_id`, `equipe_id` (text)
- `position`, `joues`, `gagnes`, `nuls`, `perdus`
- `buts_pour`, `buts_contre`, `difference_buts`, `points` (number)
- `source_donnees`, `source_maj` (text)

### 6. Sources de données
- `nom` (text), `type` (text : manual, api, official, media)
- `url`, `conditions_url`, `attribution` (text)
- `active` (boolean)

## Ordre de réalisation

1. Identifier la base réellement reliée à la publication FutPulse et le projet propriétaire.
2. Créer ou retrouver les six tables via les mécanismes 221Cloud, sans toucher à la table des actualités.
3. Accorder uniquement les permissions nécessaires à FutPulse.
4. Ajouter des routes privées protégées pour l'administration et des routes publiques en lecture seule.
5. Valider les données côté serveur et conserver source, date de mise à jour et état de vérification.
6. Afficher les matchs en indiquant clairement les données manuelles, importées ou réellement en direct.

## Garde-fous

- Ne pas inventer de scores ni de rencontres.
- Ne pas annoncer du direct sans source et synchronisation fonctionnelles.
- Ne pas appeler d'API payante ni engager de dépense sans autorisation explicite.
- Les tables et endpoints ne sont pas encore créés dans la base active : ce document est une spécification, pas une migration exécutée.
