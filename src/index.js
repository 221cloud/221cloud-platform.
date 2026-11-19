
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Vérification du fonctionnement du moteur
    if (url.pathname === "/api/health") {
      return Response.json({
        platform: "221Cloud",
        status: "online",
        message: "Le moteur 221Cloud fonctionne."
      });
    }

    // Affichage du site
    return env.ASSETS.fetch(request);
  }
};
