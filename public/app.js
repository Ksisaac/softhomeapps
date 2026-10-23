const search = document.querySelector('#search');
const category = document.querySelector('#category');
const cards = [...document.querySelectorAll('[data-product-card]')];
function filterProducts(){
  const q=(search?.value||'').toLowerCase(); const c=category?.value||'';
  cards.forEach(card=>{const okText=card.dataset.name.includes(q)||card.dataset.description.includes(q); const okCat=!c||card.dataset.category===c; card.style.display=okText&&okCat?'':'none';});
}
search?.addEventListener('input',filterProducts); category?.addEventListener('change',filterProducts);
