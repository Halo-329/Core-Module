(function () {
  const dropdown = document.querySelector('.dropdown');
  if (!dropdown) return;

  const trigger = dropdown.querySelector('.dropdown-trigger');
  const menu = dropdown.querySelector('.dropdown-menu');

  const openMenu = () => {
    menu.classList.add('open');
    trigger.setAttribute('aria-expanded', 'true');
    menu.setAttribute('aria-hidden', 'false');
  };

  const closeMenu = () => {
    menu.classList.remove('open');
    trigger.setAttribute('aria-expanded', 'false');
    menu.setAttribute('aria-hidden', 'true');
  };

  trigger.addEventListener('click', (e) => {
    e.stopPropagation();
    console.log("버튼눌림");
    menu.classList.contains('open') ? closeMenu() : openMenu();
  });

  // 바깥 클릭/ESC/스크롤 시 닫기
  document.addEventListener('click', (e) => {
    if (!dropdown.contains(e.target)) closeMenu();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeMenu();
  });
  window.addEventListener('scroll', closeMenu, { passive: true });
})();
