// NOVA icon set: geometric line icons on a 24px grid.
const P = {
  files: 'M3 7.5V18a1.5 1.5 0 0 0 1.5 1.5h15A1.5 1.5 0 0 0 21 18V9a1.5 1.5 0 0 0-1.5-1.5H11L9 5H4.5A1.5 1.5 0 0 0 3 6.5z',
  notes: 'M6 3.5h9l3.5 3.5v13.5H6zM14.5 3.5V7.5h4M9 12h6M9 15.5h6M9 8.5h2.5',
  monitor: 'M12 3l7.8 4.5v9L12 21l-7.8-4.5v-9zM7 12.5h2.5l1.5-3 2.5 5 1.5-2H17',
  settings: 'M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7zM12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.3 5.3l2.1 2.1M16.6 16.6l2.1 2.1M18.7 5.3l-2.1 2.1M7.4 16.6l-2.1 2.1',
  spark: 'M12 3c.6 4.6 2.4 7.4 9 9-6.6 1.6-8.4 4.4-9 9-.6-4.6-2.4-7.4-9-9 6.6-1.6 8.4-4.4 9-9z',
  app: 'M4.5 4.5h6v6h-6zM13.5 4.5h6v6h-6zM4.5 13.5h6v6h-6zM16.5 13.5a3 3 0 1 0 0 6 3 3 0 0 0 0-6z',
  grid: 'M5 5h3v3H5zM10.5 5h3v3h-3zM16 5h3v3h-3zM5 10.5h3v3H5zM10.5 10.5h3v3h-3zM16 10.5h3v3h-3zM5 16h3v3H5zM10.5 16h3v3h-3zM16 16h3v3h-3z',
  search: 'M10.5 4a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zM15.5 15.5L20 20',
  user: 'M12 4a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM4.5 20c.8-3.6 3.6-5.5 7.5-5.5s6.7 1.9 7.5 5.5',
  bell: 'M6 16.5V11a6 6 0 0 1 12 0v5.5l1.5 2h-15zM10 20.5a2 2 0 0 0 4 0',
  wifi: 'M3 9.5a13 13 0 0 1 18 0M6 13a8.5 8.5 0 0 1 12 0M9 16.5a4 4 0 0 1 6 0M12 20h.01',
  minimize: 'M6 12h12',
  maximize: 'M6.5 6.5h11v11h-11z',
  restore: 'M9 9V5.5h9.5V15H15M5.5 9H15v9.5H5.5z',
  close: 'M6.5 6.5l11 11M17.5 6.5l-11 11',
  upload: 'M12 16V4.5M7.5 9L12 4.5 16.5 9M4.5 15v4.5h15V15',
  download: 'M12 4.5V16M7.5 11.5L12 16l4.5-4.5M4.5 15v4.5h15V15',
  folderPlus: 'M3 7.5V18a1.5 1.5 0 0 0 1.5 1.5h15A1.5 1.5 0 0 0 21 18V9a1.5 1.5 0 0 0-1.5-1.5H11L9 5H4.5A1.5 1.5 0 0 0 3 6.5zM12 11v6M9 14h6',
  trash: 'M5 7h14M10 4h4M7 7l.8 12.5h8.4L17 7M10.5 10.5v6M13.5 10.5v6',
  edit: 'M4 20l1-4L16.5 4.5a2 2 0 0 1 3 3L8 19zM14.5 6.5l3 3',
  move: 'M12 3v18M3 12h18M8.5 6.5L12 3l3.5 3.5M8.5 17.5L12 21l3.5-3.5M6.5 8.5L3 12l3.5 3.5M17.5 8.5L21 12l-3.5 3.5',
  chevronRight: 'M9.5 6l6 6-6 6',
  chevronLeft: 'M14.5 6l-6 6 6 6',
  up: 'M12 19V5M6 11l6-6 6 6',
  plus: 'M12 5v14M5 12h14',
  file: 'M6 3.5h8.5L18.5 7.5v13H6zM14 3.5v4.5h4.5',
  image: 'M4 5.5h16v13H4zM4 16l4.5-4.5 4 4 3-3L20 17M9 9.5a1 1 0 1 0 0 .01',
  check: 'M5 12.5l4.5 4.5L19 7.5',
  refresh: 'M19.5 8A8 8 0 0 0 5 9.5M4.5 4.5v5h5M4.5 16A8 8 0 0 0 19 14.5M19.5 19.5v-5h-5',
  logout: 'M10 4.5H5.5v15H10M14 8l4 4-4 4M18 12H9',
  lock: 'M6.5 11h11v8.5h-11zM8.5 11V8a3.5 3.5 0 0 1 7 0v3',
  cpu: 'M7 7h10v10H7zM10 10h4v4h-4zM9.5 3.5v3M14.5 3.5v3M9.5 17.5v3M14.5 17.5v3M3.5 9.5h3M3.5 14.5h3M17.5 9.5h3M17.5 14.5h3',
  ram: 'M3.5 8h17v8h-17zM7 16v2.5M11 16v2.5M15 16v2.5M7 11.5h2M11 11.5h2M15 11.5h2',
  temp: 'M10 14.5V5a2 2 0 0 1 4 0v9.5a3.8 3.8 0 1 1-4 0z',
  disk: 'M4 7.5c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 7.5v9c0 1.7 3.6 3 8 3s8-1.3 8-3v-9',
  clock: 'M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16zM12 7.5V12l3 2',
  info: 'M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16zM12 11v5M12 8h.01',
  more: 'M12 6h.01M12 12h.01M12 18h.01',
  eye: 'M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12zM12 9.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5z',
  shield: 'M12 3.5l7 2.5v5.5c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6z',
  net: 'M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16zM4 12h16M12 4c2.5 2.3 3.5 5 3.5 8s-1 5.7-3.5 8c-2.5-2.3-3.5-5-3.5-8s1-5.7 3.5-8z',
  menu: 'M4.5 7h15M4.5 12h15M4.5 17h15',
};

export function icon(name, cls = '') {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', 'icon ' + cls);
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('d', P[name] || P.app);
  svg.appendChild(path);
  return svg;
}
export const hasIcon = name => name in P;
