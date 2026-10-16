"""Compounding font-size shrink check for HTML-like files (scan_sast)."""

import os
import sys

import pytest

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
sys.path.insert(0, SCRIPTS)

import scan_sast  # noqa: E402


class TestCompoundingShrink:
    @staticmethod
    def _lines(tmp_path, text):
        f = tmp_path / "a.html"
        f.write_text(text)
        return [x.line for x in scan_sast.scan_css_steganography(str(f), "a.html")]

    def test_twenty_nested_08em_is_flagged(self, tmp_path):
        css = "<style>.nest{font-size:0.8em}</style>\n"
        assert self._lines(tmp_path, css + '<div class="nest">' * 20 + "x" + "</div>" * 20)

    def test_six_nested_06em_is_flagged(self, tmp_path):
        css = "<style>.n{font-size:0.6em}</style>\n"
        assert self._lines(tmp_path, css + '<div class="n">' * 6 + "x")

    def test_inline_style_chain_is_flagged(self, tmp_path):
        assert self._lines(tmp_path, '<div style="font-size:0.7em">' * 9 + "x")

    def test_single_and_sibling_repeats_are_clean(self, tmp_path):
        css = "<style>.nest{font-size:0.8em}</style>\n"
        assert not self._lines(tmp_path, css + '<div class="nest">x</div>')
        assert not self._lines(tmp_path, css + '<div class="nest">x</div>' * 8)

    def test_large_markup_is_linear(self, tmp_path):
        import time
        css = "<style>.nest{font-size:0.8em}</style>\n"
        start = time.perf_counter()
        self._lines(tmp_path, css + "<div>" * 150000)
        self._lines(tmp_path, css + "<a " * 150000)
        assert time.perf_counter() - start < 10


class TestCompoundingMarkup:
    @staticmethod
    def _lines(tmp_path, text, name="a.html"):
        f = tmp_path / name
        f.write_text(text)
        return [x.line for x in scan_sast.scan_css_steganography(str(f), name)]

    CSS = "<style>.s{font-size:0.6em}</style>\n"

    def test_data_class_is_not_a_class(self, tmp_path):
        assert not self._lines(tmp_path, "<style>.h{font-size:0.8em}</style>\n" + '<div data-class="h">' * 30)

    def test_unquoted_class_and_gt_in_attribute(self, tmp_path):
        assert self._lines(tmp_path, self.CSS + "<div class=s>" * 7)
        assert self._lines(tmp_path, self.CSS + '<div title="a>b" class="s">' * 7)


class TestCompoundingExponents:
    CSS = "<style>.s{font-size:0.6em}</style>\n"

    @staticmethod
    def _lines(tmp_path, text, name="a.html"):
        f = tmp_path / name
        f.write_text(text)
        return [x.line for x in scan_sast.scan_css_steganography(str(f), name)]

    @pytest.mark.parametrize("size", ["0.6e0em", "6e-1em", "+.6em"])
    def test_exponent_sizes_chain(self, tmp_path, size):
        css = "<style>.s{font-size:%s}</style>\n" % size
        assert self._lines(tmp_path, css + '<div class="s">' * 8)

    def test_no_font_word_skips_the_size_helpers(self, tmp_path):
        assert self._lines(tmp_path, "<p>" + "hello <b>x</b> " * 1000) == []


class TestCompoundingClassExponents:
    @staticmethod
    def _lines(tmp_path, text, name="a.html"):
        f = tmp_path / name
        f.write_text(text)
        return [x.line for x in scan_sast.scan_css_steganography(str(f), name)]

    @pytest.mark.parametrize("size,cls", [("6e-1em", "a"), ("6e1%", "a"), ("+.6em", "a")])
    def test_exponent_class_sizes(self, tmp_path, size, cls):
        css = "<style>.a{font-size:%s}</style>\n" % size
        assert self._lines(tmp_path, css + '<div class="a">' * 8)


class TestCompoundingLabel:
    @staticmethod
    def _found(tmp_path, text):
        f = tmp_path / "a.html"
        f.write_text(text)
        return scan_sast.scan_css_steganography(str(f), "a.html")

    def test_compounding_bound_is_a_labelled_low_finding(self, tmp_path):
        css = "<style>.n{font-size:0.8em}</style>\n"
        found = self._found(tmp_path, css + '<p class="n">x</p>' * 20)
        assert [f.severity for f in found] == ["low"]
        assert "nesting not verified" in found[0].title

    def test_few_small_items_stay_clean(self, tmp_path):
        css = "<style>.n{font-size:0.8em}</style>\n"
        assert not self._found(tmp_path, css + '<p class="n">x</p>' * 8)


class TestCompoundingDeclarations:
    @staticmethod
    def _found(tmp_path, text):
        f = tmp_path / "a.html"
        f.write_text(text)
        return scan_sast.scan_css_steganography(str(f), "a.html")

    S = "<style>.s{font-size:0.8em}</style>"

    def test_entity_encoded_class_and_style_are_counted(self, tmp_path):
        assert self._found(tmp_path, self.S + '<div class="&#115;">' * 20)
        assert self._found(tmp_path, '<div style="font-size:&#48;.8em">' * 20)

    def test_important_and_later_declarations_do_not_hide_a_shrink(self, tmp_path):
        css = "<style>.s{font-size:0.8em!important;font-size:2em}</style>"
        assert self._found(tmp_path, css + '<div class="s">' * 20)

    def test_font_shorthand_is_counted(self, tmp_path):
        assert self._found(tmp_path, "<style>.s{font:0.8em sans-serif}</style>" + '<div class="s">' * 20)
        assert self._found(tmp_path, '<div style="font:0.8em/1.2 serif">' * 20)
        assert not self._found(tmp_path, '<div style="font:700 1em serif">' * 20)

    def test_class_and_style_on_one_element_count_once(self, tmp_path):
        text = self.S + '<div class="s" style="font-size:0.8em">' * 7
        assert not self._found(tmp_path, text)


class TestCompoundingSelectors:
    @staticmethod
    def _found(tmp_path, text):
        f = tmp_path / "a.html"
        f.write_text(text)
        return scan_sast.scan_css_steganography(str(f), "a.html")

    @pytest.mark.parametrize("name,text", [
        ("tag", "<style>span{font-size:.7em}</style>" + "<span>" * 8 + "x"),
        ("id", "<style>" + "".join("#i%d{font-size:.7em}" % i for i in range(8)) + "</style>"
         + "".join("<div id=i%d>" % i for i in range(8))),
        ("attr", "<style>[data-x]{font-size:.7em}</style>" + "<div data-x>" * 8),
        ("pseudo", "<style>.a:first-child{font-size:.7em}</style>" + "<div class=a>" * 8),
        ("escaped", "<style>.a\\:b{font-size:.7em}</style>" + '<div class="a:b">' * 8),
        ("hex-escape", "<style>.\\61 b{font-size:.7em}</style>" + '<div class="ab">' * 8),
        ("list", "<style>h1,.a,#z{font-size:.7em}</style>" + "<div class=a>" * 8),
        ("descendant", "<style>div .a{font-size:.7em}</style>" + "<div class=a>" * 8),
        ("calc", "" + '<div style="font-size:calc(.7em)">' * 8),
        ("smaller", '<div style="font-size:smaller">' * 16),
    ])
    def test_selector_forms_and_keywords_are_counted(self, tmp_path, name, text):
        assert self._found(tmp_path, text), name

    @pytest.mark.parametrize("text", [
        "<style>span{font-size:.7em}</style><span>x</span>",
        "<style>.a:not(.b){font-size:.7em}</style><div class=b>" * 1,
        '<div style="font-size:calc(1px + .7em)">' * 20,
        '<div style="font-size:var(--s)">' * 20,
        "<style>.a{font-size:.7em}</style>" + "<div class=other>" * 50,
    ])
    def test_unrelated_or_unfactorable_forms_stay_clean(self, tmp_path, text):
        assert not self._found(tmp_path, text)


class TestCompoundingSelectorForms:
    @staticmethod
    def _found(tmp_path, text):
        f = tmp_path / "a.html"
        f.write_text(text)
        return scan_sast.scan_css_steganography(str(f), "a.html")

    @pytest.mark.parametrize("name,text", [
        ("space", "<style>.a {font-size:.7em}</style>" + "<div class=a>" * 8),
        ("newline", "<style>.a\n{font-size:.7em}</style>" + "<div class=a>" * 8),
        ("comment", "<style>.a/* x */{font-size:.7em}</style>" + "<div class=a>" * 8),
        ("escaped-comma", "<style>.a\\,b{font-size:.7em}</style>" + '<div class="a,b">' * 8),
        ("smaller-short", "<style>.s{font:smaller sans-serif}</style>" + "<div class=s>" * 16),
        ("calc-short", "<style>.s{font:calc(.7em) serif}</style>" + "<div class=s>" * 8),
        ("italic-calc", '<div style="font:italic bold calc(.7em) serif">' * 8),
    ])
    def test_selector_trim_split_and_shorthand(self, tmp_path, name, text):
        assert self._found(tmp_path, text), name

    @pytest.mark.parametrize("text", [
        "<style>.a:not(.b,.c){font-size:.7em}</style>" + "<div class=c>" * 8,
        "<style>[hidden]{font-size:.7em}</style>" + "<div data-x=hidden>" * 8,
        '<style>[title="a,b"]{font-size:.7em}</style>' + "<div class=b>" * 8,
    ])
    def test_top_level_comma_and_attribute_values_are_not_names(self, tmp_path, text):
        assert not self._found(tmp_path, text)

    def test_subject_keys_trim_and_split(self):
        assert scan_sast._subject_keys(".a ") == [("class", "a")]
        assert scan_sast._split_selector_list(".a:not(.b,.c),.d") == [".a:not(.b,.c)", ".d"]
        assert scan_sast._split_selector_list(".a\\,b,.c") == [".a\\,b", ".c"]


class TestCompoundingDecoys:
    @staticmethod
    def _found(tmp_path, text):
        f = tmp_path / "a.html"
        f.write_text(text)
        return scan_sast.scan_css_steganography(str(f), "a.html")

    A = "<style>.a{font-size:.7em}</style>"

    @pytest.mark.parametrize("name,text", [
        ("title-decoy-before", A + '<div title="class=other" class=a>' * 8),
        ("comment-in-style", '<div style="font-size:/**/.7em">' * 8),
        ("ns-empty", "<style>[|data-x]{font-size:.7em}</style>" + "<div data-x>" * 8),
        ("ns-star", "<style>[*|data-x]{font-size:.7em}</style>" + "<div data-x>" * 8),
        ("ns-named", "<style>[ns|data-x]{font-size:.7em}</style>" + "<div data-x>" * 8),
        ("size-after-style", "<style>.a{font:italic 700 .7em/1.2 serif}</style>" + "<div class=a>" * 8),
    ])
    def test_decoys_comments_and_namespaces(self, tmp_path, name, text):
        assert self._found(tmp_path, text), name

    @pytest.mark.parametrize("text", [
        A + '<div title="class=a">' * 8,
        '<div title="style=font-size:.7em">' * 8,
        "<style>.a{font:16px/.7em serif}</style>" + "<div class=a>" * 8,
        "<style>.a{font:16px smaller}</style>" + "<div class=a>" * 16,
        '<div style="font:16px/calc(.7em) serif">' * 8,
        '<div style="content:\'font-size:.7em\'">' * 8,
    ])
    def test_attribute_values_and_later_shorthand_slots_do_not_count(self, tmp_path, text):
        assert not self._found(tmp_path, text)


class TestCompoundingBlocksAndCaps:
    @staticmethod
    def _found(tmp_path, text):
        f = tmp_path / "a.html"
        f.write_text(text)
        return scan_sast.scan_css_steganography(str(f), "a.html")

    @pytest.mark.parametrize("css", [
        ".a{font-size:70%;&.b{color:red}}",
        ".a{&.b{color:red}font-size:70%}",
        ".a{@media screen{color:red}font-size:70%}",
        ".a{f\\6fnt-size:70%}",
        ".a{font-size:7\\30 %}",
    ])
    def test_nested_blocks_and_escapes(self, tmp_path, css):
        assert self._found(tmp_path, "<style>" + css + "</style>" + "<div class=a>\n" * 14)

    def test_input_caps_report_instead_of_dropping(self, tmp_path):
        big = " " * 3_000_000 + "<style>.a{font-size:70%}</style>" + "<div class=a>\n" * 14
        assert any("too large" in f.title for f in self._found(tmp_path, big))
        wide = "<style>.a{font-size:70%}</style><div " + "x=1 " * 6000 + "class=a>\n"
        assert any("too large" in f.title for f in self._found(tmp_path, wide))


class TestReviewRound1:
    @staticmethod
    def _found(tmp_path, text, name="a.html"):
        f = tmp_path / name
        f.write_text(text)
        return scan_sast.scan_css_steganography(str(f), name)

    def test_jsx_classname_counts_as_class(self, tmp_path):
        css = "<style>.s{font-size:0.6em}</style>\n"
        assert self._found(tmp_path, css + '<div className="s">' * 8, "a.jsx")

    @pytest.mark.parametrize("style", [
        "style={{fontSize: '0.7em'}}",
        "style={{ 'font-size': '70%' }}",
        'style={{"font-size": "0.7em"}}',
    ])
    def test_jsx_style_objects_count(self, tmp_path, style):
        assert self._found(tmp_path, "<div %s>" % style * 9, "a.tsx")

    def test_long_selector_list_is_not_dropped(self, tmp_path):
        pad = ",".join(".x%d" % i for i in range(400))      # well over 1000 characters
        css = "<style>%s,.s{font-size:0.6em}</style>\n" % pad
        assert self._found(tmp_path, css + '<div class="s">' * 8)

    @pytest.mark.parametrize("where", ["style-block", "inline-style"])
    def test_long_digit_runs_are_linear(self, tmp_path, where):
        import time
        digits = "1" * 60000
        if where == "style-block":
            text = "<style>.a{font-size:%sem}</style>\n<div class=a>" % digits
        else:
            text = '<div style="font-size:%sem">' % digits
        start = time.perf_counter()
        self._found(tmp_path, text)
        self._found(tmp_path, "<style>.a{font:bold %sem x}</style>" % digits)
        assert time.perf_counter() - start < 2.0

    def test_entity_encoded_font_word_still_reaches_the_check(self, tmp_path):
        assert self._found(tmp_path, '<div style="&#102;ont-size:0.7em">' * 9)

    def test_compound_selector_needs_every_key(self, tmp_path):
        css = "<style>td.small{font-size:0.6em}</style>\n"
        assert not self._found(tmp_path, css + "<td>x</td>" * 40 + '<td class="small">y</td>')
        assert self._found(tmp_path, css + '<td class="small">y</td>' * 8)

    def test_attribute_compound_does_not_count_every_tag(self, tmp_path):
        css = "<style>a[href^=http]{font-size:0.6em}</style>\n"
        assert not self._found(tmp_path, css + "<a>x</a>" * 40 + '<a href="http://x">y</a>')
        assert self._found(tmp_path, css + '<a href="http://x">y</a>' * 8)

    def test_many_compounds_on_one_key_stay_bounded(self, tmp_path):
        import time
        rules = "".join("div.c%d{font-size:0.9em}" % i for i in range(3000))
        start = time.perf_counter()
        self._found(tmp_path, "<style>%s</style>\n" % rules + '<div class="c1">' * 20000)
        assert time.perf_counter() - start < 5.0

    RULE = "<style>.s{font-size:0.5em}</style>\n"
    ELEMS = '<p class="s">x</p>' * 30

    def test_commented_style_rule_is_not_live(self, tmp_path):
        assert not self._found(tmp_path, "<!-- " + self.RULE + "-->\n" + self.ELEMS)

    def test_commented_elements_are_not_counted(self, tmp_path):
        assert not self._found(tmp_path, self.RULE + "<!-- " + self.ELEMS + " -->")

    @pytest.mark.parametrize("tag", ["script", "textarea", "template", "title", "noscript"])
    def test_inert_bodies_are_not_counted(self, tmp_path, tag):
        body = "<%s>%s</%s>" % (tag, self.ELEMS, tag)
        assert not self._found(tmp_path, self.RULE + body)

    def test_controls_and_live_rules_still_flag(self, tmp_path):
        assert not self._found(tmp_path, self.RULE.replace("0.5em", "0.9em") + '<p class="s">x</p>' * 5)
        assert self._found(tmp_path, self.RULE + self.ELEMS)
        assert self._found(tmp_path, "<style><!-- .s{font-size:0.5em} --></style>\n" + self.ELEMS)
        assert self._found(tmp_path, "<!-- c -->" + self.RULE + self.ELEMS)

    def test_fake_style_inside_a_comment_is_not_style_context(self, tmp_path):
        prefix = "<!-- <style> --><!-- .s{font-size:0.5em} -->"
        assert not self._found(tmp_path, prefix + self.ELEMS)

    NEST = '<span class="small">' * 8 + "ordinary text" + "</span>" * 8
    SMALL = "<style>.small{font-size:.7em}</style>"

    def test_rules_inside_inert_bodies_do_not_leak(self, tmp_path):
        tpl = '<template id="p">' + self.SMALL + "<p>x</p></template>\n"
        assert not self._found(tmp_path, tpl + self.NEST)
        scr = '<script type="text/plain">.small{font-size:.7em}</script>\n'
        assert not self._found(tmp_path, scr + self.NEST)

    def test_nested_template_is_tracked_by_depth(self, tmp_path):
        doc = self.SMALL + "\n<template><template></template>" + self.NEST + "</template>"
        assert not self._found(tmp_path, doc)
        assert self._found(tmp_path, self.SMALL + "\n" + self.NEST)

    @pytest.mark.parametrize("prefix", [
        '<script>const t = "<style>";</script>\n<!-- .small{font-size:.7em} -->\n',
        '<div data-example="<style>"></div>\n<!-- .small{font-size:.7em} -->\n',
    ])
    def test_style_text_in_script_or_attribute_is_not_a_marker(self, tmp_path, prefix):
        assert not self._found(tmp_path, prefix + self.NEST)

    def test_comment_open_in_script_does_not_hide_a_live_style(self, tmp_path):
        doc = '<script>const c = "<!--";</script>\n' + self.SMALL + "\n" + self.NEST
        assert self._found(tmp_path, doc)

    INNER = '<span style="font-size:0.5em">' * 12 + "x" + "</span>" * 12

    def test_vue_top_level_template_is_live(self, tmp_path):
        p = tmp_path / "App.vue"
        p.write_text("<template>" + self.INNER + "</template>")
        assert [f for f in scan_sast.scan_css_steganography(str(p), "App.vue") if "compounding" in f.title]

    @pytest.mark.parametrize("tag", ["title", "script", "textarea", "noscript", "template"])
    def test_unclosed_mention_does_not_blank_to_eof(self, tmp_path, tag):
        doc = "Use the <%s> tag.\n" % tag + self.INNER
        assert self._found(tmp_path, doc)

    @pytest.mark.parametrize("tag", ["script", "template", "textarea", "title", "noscript"])
    def test_many_unclosed_tags_are_linear(self, tag):
        import time
        text = ("<%s>" % tag) * 200000
        start = time.perf_counter()
        scan_sast._blank_dead_markup(text)
        assert time.perf_counter() - start < 2.0

    def test_inert_regions_survive_an_unclosed_template_mention(self, tmp_path):
        head = "Use the <template> tag.\n"
        assert not self._found(tmp_path, head + "<!-- " + self.INNER + " -->")
        for tag in ("script", "textarea", "title", "noscript"):
            body = "<%s>%s</%s>" % (tag, self.INNER, tag)
            assert not self._found(tmp_path, head + body), tag
        assert self._found(tmp_path, head + self.INNER)

    def test_live_jsx_next_to_comment_openers_in_strings_still_flags(self, tmp_path):
        p = tmp_path / "S.tsx"
        spans = '<span style={{fontSize: "50%"}}>' * 6 + "x" + "</span>" * 6
        p.write_text("const re = '{/*';\nexport const C = () => (<div>" + spans + "</div>);\nconst c = '*/}';\n")
        assert [f for f in scan_sast.scan_css_steganography(str(p), p.name) if "compounding" in f.title]
