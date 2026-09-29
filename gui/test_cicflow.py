from cicflowmeter.flow_session import FlowSession
from cicflowmeter.features.context.packet_direction import PacketDirection
import warnings
warnings.filterwarnings('ignore')

print("CICFlowMeter import OK!")
print("Version check complete")

# Features list dekho
from cicflowmeter.features.flow_bytes import FlowBytes
print("FlowBytes OK!")

from cicflowmeter.features.packet_time import PacketTime
print("PacketTime OK!")