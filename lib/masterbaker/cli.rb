require "librarian/chef/cli"
require "masterbaker/remote_config"
require "awesome_print"
require "thor"

class Thor::Shell::Color
    def say(string, color=:WHITE, nl=true, prefix=true)

      if prefix
        #super '★', :green, false
        super ' Masterbaker ', :white, false
        #super '★', :green, false
        super ':: ', :white, false
      end

      super(string, color, nl)
    end
end

module Masterbaker

    class CLI < Thor
    attr_writer :masterbaker_config
    default_task :chef


    desc "chef", "Run chef-solo"
    method_option :remote, :aliases => "-r", :desc => "Run chef-solo on user@host"
    method_option :identity, :aliases => "-i", :desc => "The SSH identity file"
    def chef
      #begin
        say 'Masterbaker is Fetching Cookbooks', :green, true, false
        install_cookbooks if cheffile_exists?        
        say 'Masterbaker is Preparing to Bake', :green, true, false
        masterbaker_config.run_chef
      #rescue Exception => msg 
      #  say msg.backtrace.inspect  
      #  say ' Your Bakery files were not found. Please make sure ', :RED, false
      #  say '~/.bakery/', :YELLOW, false, false
      #  say ' exists', :RED, true, false
      #  say '', nil, nil, false
      #end
    end

    desc "run_recipe [cookbook::recipe, ...]", "Run individual recipes"
    method_option :remote, :aliases => "-r", :desc => "Run recipes on user@host"
    method_option :identity, :aliases => "-i", :desc => "The SSH identity file"
    def run_recipe(*recipes)
      masterbaker_config.royal_crown.recipes = recipes
      chef
    end

    desc "config", "Dumps configuration data for Masterbaker"
    def config
      Kernel.ap(masterbaker_config.as_node_json)
    end

    no_tasks do
      def install_cookbooks

        Dir.chdir(File.dirname(config_path)) do
          Librarian::Chef::Cli.with_environment do
            Librarian::Chef::Cli.new.install
          end
        end

        if user_config_path
          say 'Masterbaker is Fetching User-Specific Cookbooks', :green, true, false
          begin
            Dir.chdir(File.dirname(user_config_path)) do
              Librarian::Chef::Cli.with_environment do
                libchef = Librarian::Chef::Cli.new.install
              end
            end
          rescue
            say 'Error getting user-specific cookbooks, scratching.', :red
            abort
          end
        end

      end

      def masterbaker_config
        @masterbaker_config ||= if options[:remote]
          Masterbaker::RemoteConfig.from_file(config_path, remote)
        else
          Masterbaker::Config.from_file(config_path)
        end.tap do |config|
          config.merge!(user_config) if user_config_path
          config.merge!(shop_config) if shop_config_path
          #config.merge!(shop_managed_user_config) if shop_managed_user_config_path
        end
      end
    end

    private
    def shop_config
      Masterbaker::Config.from_file(shop_config_path)
    end    

    def user_config
      Masterbaker::Config.from_file(user_config_path)
    end

    def shop_managed_user_config
      Masterbaker::Config.from_file(shop_managed_user_config_path)
    end

    def remote
      @remote ||= if options[:identity]
        Masterbaker::Remote.from_uri(options[:remote], options[:identity])
      else
        Masterbaker::Remote.from_uri(options[:remote])
      end
    end

    def cheffile_exists?
      File.exists?(File.expand_path("~/.bakery/Cheffile"))
    end

    def config_path
      @config_path ||= File.expand_path("~/.bakery/bakeryrc")
    end

    # TODO: Fix librarian cookbook path defaults
    def shop_managed_user_config_path
    #  current_user = ENV['SUDO_USER'] ||= ENV['USER']
    #  shop_managed_user_config_path = File.expand_path("~/.bakery/bakers/#{current_user}/bakeryrc")
    #  if File.exists?(shop_managed_user_config_path)
    #    @shop_managed_user_config_path ||= shop_managed_user_config_path
    #  end
    end

    def user_config_path
      user_config_path = File.expand_path("~/.masterbaker/masterbakerrc")
      if File.exists?(user_config_path)
        @user_config_path ||= user_config_path
      end
    end

    def shop_config_path
      shop_config_path = File.expand_path("~/.bakery/shoprc")
      if File.exists?(shop_config_path)
        @shop_config_path ||= shop_config_path
      end
    end

    def logo
      say '                                                                                                             ', :green, true, false
      say '                kkkkk                                                                                        ', :green, true, false
      say '           kbbbaaaaaaaabk                      kkkkk                                                         ', :green, true, false
      say '         kaabkbaaabkbaaaak                    baaaak                                                         ', :green, true, false
      say '       kaaak kaaaab  kaabb                   kaaaab                                                          ', :green, true, false
      say '      kbaab kbaaaak kbaab      kkbbbkkbbbb   baaaak   kbbk      kkbbbbk  kbbbkkkkbbk kbbbk  kbbbbk           ', :green, true, false
      say '      kabab kaaaaabaaaab     kaaaaaaaaaaab  kaaaaa kbaabk     baaabbaaakkbaaaaaaaaaabaaaak kbaaabk           ', :green, true, false
      say '   k   kbbkkbaaaabaaaaaaak  baaaak kbaaaak  baaaabbaabk     kbaaab kbaakkaaaabkbaabbaaaaa  baaaab      k     ', :green, true, false
      say ' kbaabk    kaaaab  kbaaaaakbaaaak  kaaaaak kbaaaaaaaaaaak  kbaaaakkbaakkbaaaak  kkkbaaaak kbaaaak   kbaabk   ', :green, true, false
      say ' kaaab     baaaak   kbaaaakaaaab   baaaab  kaaaabkbaaaaab  baaaaababk  kaaaab     kaaaaa  kaaaab     baaak   ', :green, true, false
      say '  k kk    kaaaab    kaaaabbaaaak  kaaaaa  kbaaaak  baaaak kaaaaakkk   kbaaaak     kaaaak  baaaak     kk k    ', :green, true, false
      say '          baaaabbkkkbaaabkaaaaaakbbaaaabkkbaaaab  kaaaaabkbaaaaabkkkkbbaaaab      baaaabbbaaaab              ', :green, true, false
      say '         kbaaaabaaaaaabk  baaaaaaabaaaaaaaaaaaak  kaaaaaaabaaaaaaaaabkbaaaak      baaaaaabaaaak              ', :green, true, false
      say '         kbbbbkkbbaabk     kbbbbk  kbbbbkkbbbbk    kbbbbbk  kbbbbbkk  bbbbk        kbbbkkaaaaa               ', :green, true, false
      say '                              kkkkkkbbbbbbbbbbbbbbbkkkkkkkk                            kbaaaak               ', :green, true, false
      say '                       kkbbbbbbbaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbkkk             kkkbaaaabk                ', :green, true, false
      say '                  kbbaabbbbbaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbaaaaaaaabk                  ', :green, true, false
      say '              kkbaabbbbbaaaaaaaaaaaaaaaaaaaabbbbbbbbkkkkkbbbbbbbbbbaaaaaaaaaaaaaaaaaaabkk                    ', :green, true, false
      say '            kbaaaabbbaaaaaaaaaaaaaaabbkkkk                            kkkbbbbbbbbbkkk                        ', :green, true, false
      say '           kbbbbbaaaaaaaaaaaaaabbkk                                                                          ', :green, true, false
      say '                 kkbbaaaaaabbkk                                                                              ', :green, true, false
      say '                     kbaabk                                                                                  ', :green, true, false
      say '                       kk                                                                                    ', :green, true, false
      say '                                                                                                             ', :green, true, false
      say 'Preparing...                                                                                                 ', :white, true
      say '                                                                                                             ', :green, true, false
    end

  end
end
