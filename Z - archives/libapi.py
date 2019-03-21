import copy, StringIO, json
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace

registry.PluginImporter()

def get_json(config, plugin_class):
   strio = StringIO.StringIO()
   plugin = plugin_class(copy.deepcopy(config))
   plugin.render_json(strio, plugin.calculate())
   return json.loads(strio.getvalue())

def get_config(profile, target_path):
   config = conf.ConfObject()
   registry.register_global_options(config, commands.Command)
   registry.register_global_options(config, addrspace.BaseAddressSpace)
   config.parse_options()
   config.PROFILE = profile
   config.LOCATION = "file://{0}".format(target_path)
return config 