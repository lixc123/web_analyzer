"""JavaScript代码美化工具"""
import jsbeautifier

def beautify_js(code: str) -> str:
    """美化JavaScript代码"""
    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    opts.space_in_empty_paren = True
    return jsbeautifier.beautify(code, opts)
