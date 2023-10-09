---
title: "[Ruby] Ruby와 Rails "
layout: archive
permalink: categories/ruby
author_profile: true
sidebar_main: true
---

<!-- 공백이 포함되어 있는 카테고리 이름의 경우 site.categories.['a b c'] 이런식으로! -->

***

{% assign posts = site.categories.['Ruby'] %}
{% for post in posts %} {% include archive-single2.html type=page.entries_layout %} {% endfor %}

<!-- ( 폴더 이름은 category-c-question.md  -> 연관성을 찾지못함 ( 이상하게 바꿔도 정상적으로 작동했기때문 ) ) -->