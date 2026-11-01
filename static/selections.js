(function () {
  function initialize(root) {
    const $ = window.django && window.django.jQuery;
    if (!$ || !$.fn.select2) return;
    $(root).find('select.opn-select').each(function () {
      if ($(this).hasClass('select2-hidden-accessible')) return;
      $(this).select2({tags: this.dataset.tags === 'true', width: 'resolve', placeholder: 'Type to search…', tokenSeparators: [','], allowClear: true});
    });
  }
  document.addEventListener('DOMContentLoaded', function () { initialize(document); });
  document.addEventListener('formset:added', function (event) { initialize(event.target); });
})();
