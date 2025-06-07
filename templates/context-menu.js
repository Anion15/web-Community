/* context-menu.js  (v1.0.0)
   Lightweight custom context-menu helper – no dependencies except the DOM. */
(function (root, factory) {
  if (typeof module === 'object' && typeof module.exports === 'object') {
    // CommonJS / Node
    module.exports = factory();
  } else if (typeof define === 'function' && define.amd) {
    // AMD / RequireJS
    define([], factory);
  } else {
    // Browser global
    root.ContextMenu = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /** 초기화
   * @param {Object} opts
   * @param {string} [opts.menu='#popMenu']  메뉴 DOM 선택자
   * @param {boolean} [opts.closeOnScroll=true]  스크롤 시 닫기
   */
  function init(opts = {}) {
    const {
      menu = '#popMenu',
      closeOnScroll = true
    } = opts;

    const popMenu = typeof menu === 'string' ? document.querySelector(menu) : menu;
    if (!popMenu) {
      console.warn('[ContextMenu] menu element not found.');
      return;
    }
    // 최초엔 숨겨두기
    popMenu.style.display = 'none';

    // 우클릭 → 메뉴 표시
    document.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      const { clientX, clientY } = e;

      // 뷰포트 벗어나지 않도록 위치 보정
      const { offsetWidth: mw, offsetHeight: mh } = popMenu;
      const maxX = window.innerWidth - mw - 10;
      const maxY = window.innerHeight - mh - 10;
      popMenu.style.left = `${Math.min(clientX, maxX)}px`;
      popMenu.style.top  = `${Math.min(clientY, maxY)}px`;

      popMenu.style.display = 'block';
      popMenu.style.animation = 'fadeInSlide 0.25s ease forwards';
    });

    // 외부 클릭·터치 → 닫기
    ['click', 'touchstart'].forEach(evt =>
      document.addEventListener(evt, (e) => {
        if (!popMenu.contains(e.target)) popMenu.style.display = 'none';
      })
    );

    // 창 크기 변경·(옵션) 스크롤 → 닫기
    window.addEventListener('resize', () => (popMenu.style.display = 'none'));
    if (closeOnScroll) window.addEventListener('scroll', () => (popMenu.style.display = 'none'));
  }

  // 라이브러리 공개 API
  return { init };
}));
