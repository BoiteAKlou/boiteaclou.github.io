---
layout: page
title: Categories
permalink: /categories/
---

<section class="categories-list">
<ul>
   {% for cat in site.category %}
   <li>
       <a href="/category/{{ cat.tag | downcase }}">{{ cat.fullname }}</a>
       <span class="category-description">- <em>{{ cat.description }}</em></span>
   </li>
   {% endfor %}
</ul>
</section>
