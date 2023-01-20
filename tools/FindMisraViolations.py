import sys
import argparse
import json
import linecache

def parse_MISRA_config_file( MISRA_config_file_path, list_of_suppressed_rules, list_of_suppressed_directives ):
    
    with open( MISRA_config_file_path ) as config_file:
        data = json.load(config_file)

        for rule in data['deviations']:
            if rule is not None:
                # The config file is a json readable file with 'deviation' key having a value
                # with representation in a form such as: 'Rule 21.2' OR 'Directive 1.2'.
                rule_or_directive_number = rule['deviation'].split(' ')[ 1 ]
                rule_or_directive = rule['deviation'].split(' ')[ 0 ]

                if "Rule" in rule_or_directive:
                    if rule_or_directive_number is not None:
                        list_of_suppressed_rules.append( rule_or_directive_number )
                else:
                    if rule_or_directive_number is not None:
                        list_of_suppressed_directives.append( rule_or_directive_number )

    return list_of_suppressed_rules, list_of_suppressed_directives

def IsSuppressionStatementPresent( file_with_violation, line_number, rule_number ):

    ViolationSuppressed = False
    currentLineNumber = line_number - 1

    while True:

        # Make sure we do not go beyond the file.
        if currentLineNumber < 0:
            break

        # getline starts counting from 0. Thus, we need to subtract 1 to get to the exact line.
        # Additionally, we need to subtract 1 more to get to the line above the line with violation.
        line = linecache.getline( file_with_violation, currentLineNumber )

        if not line:
            break

        # Make sure that this is a comment that we are looking at.
        if line.lstrip().startswith('/*'):
            if "coverity[misra_c_2012" in line:
                # A suppression looks like: "/* coverity[misra_c_2012_rule_11_3_violation] */"
                # The below line gets the 11_3 part from the line.
                violation_string = ( line.split( "coverity[misra_c_2012_rule_" )[ 1 ] ).split( "_violation" )[ 0 ]

                # This following line replaces the '_' with a '.'
                formatted_violation = violation_string.split('_')[0] + "." + violation_string.split('_')[1]

                if formatted_violation == rule_number:
                    ViolationSuppressed = True
                    break
        else:
            # If this is not a comment, then we do not need to read any further.
            break

        currentLineNumber -= 1
        
    return ViolationSuppressed

def find_new_violations( MISRA_report, allowed_violations, list_of_suppressed_rules, list_of_suppressed_directives ):
    list_of_new_violations = []
    with open( MISRA_report ) as report_fd:
        while True:
            found_match = False

            line = report_fd.readline()

            if not line:
                report_fd.close()
                break

            # If this is actually an entry for a rule violation...
            if ( "use --rule-texts" in line ) and ( "misra-c2012-" in line ):
                # One entry in the report looks similar to:
                # [FreeRTOS_ARP.c:1] (style) misra violation (use --rule-texts=<file> to get proper output) (Undefined) [misra-c2012-3.1]
                file_with_violation = (line.split(':')[0])[1:]
                split_line = line.split(':')[1]

                line_number = 0

                for digit in split_line:
                    if digit.isdigit() == True:
                        line_number = ( line_number * 10 ) + int( digit )
                    else:
                        # We have reached a non numerical character
                        break

                rule_number = line.split("misra-c2012-")[ 1 ]
                rule_number = rule_number.split(']')[ 0 ]

                # First see whether this violation is allowed (e.g. something which cppcheck doesn't quite understand).
                if allowed_violations is not None:
                    # If the file has the rule number on the given line suppressed...
                    if ( file_with_violation in allowed_violations ) and ( rule_number in allowed_violations[file_with_violation] ):
                        if str( line_number ) in allowed_violations[file_with_violation][rule_number]:
                            # ... then mark it to be found.
                            found_match = True
                        # Otherwise if this rule is suppressed for this whole file...
                        elif "*" in allowed_violations[file_with_violation][rule_number]:
                            # ... then mark it to be found.
                            found_match = True
                    elif rule_number in allowed_violations:
                        # This rule is globally suppressed.
                        if "*" in allowed_violations[rule_number]:
                            found_match = True
                    else:
                        # Nothing to be found
                        pass

                # First try to find the rule in the list of suppressed rules in the coverity config.
                if found_match is False:
                    if list_of_suppressed_rules is not None:
                        if rule_number in list_of_suppressed_rules:
                            found_match = True
            
                # Otherwise try to look for coverity suppression statement.
                if found_match is False:
                    found_match = IsSuppressionStatementPresent( file_with_violation, line_number, rule_number )

                if found_match is False:
                    print( file_with_violation + ":" + str( line_number ) + "  " + rule_number )
                    list_of_new_violations.append(line)
                else:
                    # print( file_with_violation + ":" + str( line_number ) + "  " + rule_number + "  Suppressed" )
                    pass
    
    return list_of_new_violations

if __name__ == "__main__":
    my_rule_list = []
    my_directive_list = []

    print(sys.argv)
    assert( len(sys.argv) is 3 )
    print( "MISRA Config file provided: " + str( sys.argv[ 1 ] ) )
    print( "MISRA.md file provided: " + str( sys.argv[ 2 ] ) )

    MISRA_config_file = str( sys.argv[ 1 ] )
    MISRA_report = str( sys.argv[ 2 ] )

    allowed_violation = { "12.3":["*"],
                          "FreeRTOS_ARP.c" : { "21.6":["35"], "11.8":[ '*' ] },
                        }

    my_rule_list, my_directive_list = parse_MISRA_config_file( MISRA_config_file, my_rule_list, my_directive_list )

    my_rule_list.sort()

    my_directive_list.sort()

    new_violations = find_new_violations( MISRA_report, None, my_rule_list, my_directive_list )
    print( "Total new violation introduced: " + str( len( new_violations ) ) )
