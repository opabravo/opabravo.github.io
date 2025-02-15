[:documents, :pages].each do |hook|
  Jekyll::Hooks.register hook, :post_render do |item|
    if item.output_ext == ".html"
      content = item.output
      site_url = item.site.config['url']
      whitelist = ['localhost', 'opabravo.github.io'] # Whitelisted prefixes

      content.gsub!(%r{<a\s+href="((?!#{whitelist.map { |d| Regexp.escape(d) }.join('|') })https?:\/\/[^"]+)"(?![^>]*rel=)}, 
                    "<a href=\"\\1?ref=#{site_url.gsub('https://', '')}\" target=\"_blank\" rel=\"nofollow noopener noreferrer\"")

      # Update the item content
      item.output = content
    end
  end
end
