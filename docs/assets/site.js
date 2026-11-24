(() => {
  const root = document.documentElement;
  const toggle = document.getElementById("langToggle");
  const menu = document.getElementById("menuToggle");
  let english = false;

  function setLanguage(useEnglish) {
    english = useEnglish;
    root.lang = english ? "en" : "ar";
    root.dir = english ? "ltr" : "rtl";

    document.querySelectorAll("[data-ar][data-en]").forEach((node) => {
      node.textContent = english ? node.dataset.en : node.dataset.ar;
    });

    if (toggle) toggle.textContent = english ? "العربية" : "English";
    document.title = document.body.dataset[english ? "titleEn" : "titleAr"] || document.title;
  }

  if (toggle) toggle.addEventListener("click", () => setLanguage(!english));
  if (menu) menu.addEventListener("click", () => {
    document.querySelector(".nav-links")?.classList.toggle("open");
  });

  document.querySelectorAll(".nav-links a").forEach((link) => {
    link.addEventListener("click", () => {
      document.querySelector(".nav-links")?.classList.remove("open");
    });
  });

  setLanguage(false);
})();
