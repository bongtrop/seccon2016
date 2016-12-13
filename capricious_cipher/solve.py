from liblll import *

P = 79228162514264337593543950319
pub = [14883097866997387203089669453,[29564268724766561187346611934,32713792361604504806493431434,76231531289345241885041648136,29544347612938517192649479706,16494530396078625297698541127,1423895337199990791414795154,45018682314282733760644439841,15706965977286204678793829122,49297894944235752641158044086,66526615620574946602517565870,3739639907030154032161322858,8494209705638083528620918243,61554667924511751194871120962,20490737422054035002944460456,76328897807971393764430519825,23057237662555305319472826998,60965743745540175180368273010,44779303101736918478719963461,7976208853186645140542357350,14898031749497230825037440955,60899966420437930748267663978,45578288121038585028032317673,6197317415628715749347904170,4539892486518804276246411940,35085040991764716570671713287,19473977723365483342449465404,71233940488539423785496699147,20528182225998929397695877880,66900661971538429136721988272,23640073464090944715321461586,19046721467951824969912837578,37247622481593304863570152066,54901305606084493064653505824,17253052521992806502963626926,26776716082893962363465638497,58518866876854669707785316780,14604538369772224770095412636,13343600183059493980350991364,53101089735384372796817872689,65188502619790048812129282944,46446374486256602803452673564,914695799917893568488942568,57983664581536145630087497495,61491586439562017794007105334,139943706358333193092448894,71548855295050501634121524188,38047672578526037222610454588,2240266241824140064754642878,7361251889659911500931921526,21008238938673759943778210020,13304826175672593355945167894,53600130568187337236515355936,13296831462353055859703077275,54780350605483910668170089230,36832765521045842985921786096,17704127983956581854801743285,67284858831810822590387033361,59718142433118795819092747887,15978669172350540822316166802,33711991229569988489619706333,61239111569917918960069117585,75847603119455281605881952929,45234748999583727629997413936,19925600437485709893496097468,8370862833163310309846666791,2690165530118958724995090637,54610281967658017579688092962,12359763185649755028361842824,69700123727887346821865358952,40548258604028330235460937364,40345665774208113143701180141,23709594550367913634977191905,39231920288058014291825708614,37312064023620197272999819703,10185488487886582017799934854,17578522915997145266232247851,29665858761495121827587419711,72265260688678319022515926136,16205635390556317512550259104,48329791957006834234463144590,64574610967795589934132936317,62503727501907249673068092647,25062798937101305906984473439,53605492172131961826782987670,19056182109846694022108101953,21760049264298446517555203435,72040466884479732329998002781,7393068812751233224263696641,14064903310286056124512383478,35945759230323163182379853619,78924831548061569064169972581,44754085419990003082650829087,18635611978769919339152407610,71378468392822175968939818644,75629299125191815275894722991,68865034705932764538085749303,21865017681678961874651405779,20947865371712904696662607982,64632569950791965015415887906,78229785072447052087890286932,59247616826111885716260270247,25402114840624576572296977514,4687812137255670280040714390,1096990599723865046487091052,41109742929715556464695293303,13884909119110726482628019695,76645771622602089732002958027,41031408632321325462742792309,23472203735686206697373731053,47564663619466140825691225461,259222406476334253707964567,59892769495755845722423869148,48282184791248308934467079985,26804512716864179034057620753,55761517234150058108964706616,33908054312864296396022631843,10650329498146398092615132626,33541403618265415006147178021,53264158222265083654627988320,5371308455865086066657027404,49265011213400785509256268376,40325310468098943962073016235,13004459326385387103318133095,54672140282465402263082706663,54436542489210997108961047207,2208452846491072825560702190,6599718948063867334841785363,19910766768118417645710628313]]

s = 0

for n in pub[1]:
    s+=n

for i in range(6, s/P):
    mat = create_matrix_from_knapsack(pub[1], P*i + pub[0])
    mat_red = lll_reduction(mat)
    best_vector = best_vect_knapsack(mat_red)
    print i, best_vector