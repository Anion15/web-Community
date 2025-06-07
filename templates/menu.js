(function () {
  const menuItems = [
    { label: "🏠 홈으로 가기", url: "/" },
    { label: "📘 소개 및 이용규칙", url: "/info" },
    { label: "📊 통계 및 정보", url: "/history" },
    { label: "☕ 후원하기", url: "https://buymeacoffee.com/sjinside" },
  ];

  const style = document.createElement("style");
  style.innerHTML = `
    #custom-context-menu {
      position: absolute;
      display: none;
      width: 280px;
      backdrop-filter: blur(10px);
      background: rgba(255, 255, 255, 0.15);
      border-radius: 12px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
      animation: fadeInSlide 0.3s ease forwards;
      overflow: hidden;
      z-index: 9999;
      font-family: 'Segoe UI', sans-serif;
    }

    @keyframes fadeInSlide {
      from { opacity: 0; transform: translateY(-10px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .custom-menu-item {
      display: block;
      padding: 10px 16px;
      color: white;
      text-decoration: none;
      background: transparent;
      transition: all 0.3s ease;
    }

    .custom-menu-item:hover {
      background: rgba(255, 255, 255, 0.2);
      font-weight: bold;
      transform: scale(1.02);
    }
  `;
  document.head.appendChild(style);

  const menu = document.createElement("div");
  menu.id = "custom-context-menu";

  menuItems.forEach(item => {
    const link = document.createElement("a");
    link.href = item.url;
    link.innerText = item.label;
    link.className = "custom-menu-item";
    menu.appendChild(link);
  });

  document.body.appendChild(menu);

  document.addEventListener("contextmenu", e => {
    e.preventDefault();
    menu.style.top = `${e.pageY}px`;
    menu.style.left = `${e.pageX}px`;
    menu.style.display = "block";
    menu.style.animation = "fadeInSlide 0.3s ease forwards";
  });

  document.addEventListener("click", e => {
    if (!menu.contains(e.target)) {
      menu.style.display = "none";
    }
  });

  window.addEventListener("resize", () => {
    menu.style.display = "none";
  });
})();
