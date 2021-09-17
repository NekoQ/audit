require 'json'

def parse(audit)
  items = []
  item = ''
  audit.each_line do |line|
    unless line.start_with?('#')
      if line.include? '<custom_item>'
        item = ''
      elsif line.include? '</custom_item'
        items << item.dup
      else
        item << line
      end
    end
  end
  split_rules(items)
end

def split_rules(items)
  new_items = []
  items.each do |item|
    h = {}
    item.split("\n ").each do |line|
      splitted = line.split(' : ')
      h[splitted.first.strip] = splitted.last.strip
    end
    new_items << h.dup
  end
  new_items
end

def import
  help_string = "  import {audit file name} {new name}\n  exit"
  input = ''
  until input.start_with? 'exit'
    input = gets.chomp
    puts help_string if input.start_with? 'help'
    next unless input.start_with? 'import'

    file_name = input.split[1]
    json_name = input.split[2]
    generate_json(file_name, json_name)
  end
end

def generate_json(file_name, json_name)
  file = File.open(file_name)
  items = parse(file)
  File.open("Polices/#{json_name}.json", 'w') do |f|
    f << JSON.pretty_generate(items)
    puts "#{json_name}.json generated"
  end
end

import
