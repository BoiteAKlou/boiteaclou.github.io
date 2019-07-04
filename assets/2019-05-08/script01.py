def finished(coverage):
    for i in range(1,10001):
        if not coverage[i]:
            return False
    return True

def solution_covers(solution,line):
    for router in solution:
        if router in line:
            return True
    return False

def get_unique_routers_list():
    routers = []
    lines = open('routes.txt','r').readlines()
    for line in lines:
        splitted = line.strip().split(',')
        for router in splitted:
            if router not in routers:
                routers.append(router)
    #print(routers)
    print(str(len(routers))+" unique routers")
    return routers

def count_router_occurences(routers_list):
    occurences = {}
    f = open('routes.txt','r')
    lines = f.read()
    for router in routers_list:
        occurences[router] = lines.count(router)
    f.close()
    sorted_occurences = [(k, occurences[k]) for k in sorted(occurences, key=occurences.get, reverse=True)]
    return sorted_occurences

def get_best_router_of_line(router_occurences,routers_list):
    best_router = ('router',0)
    for router in routers_list:
        if router_occurences.get(router)>best_router[1]:
            best_router = (router,router_occurences.get(router))
    return best_router



if __name__ == "__main__":
    solution = []
    is_covered = {}

    unique_routers = get_unique_routers_list()
    router_occurences = count_router_occurences(unique_routers)

    #init is_covered
    for i in range(1,10001):
        is_covered[i] = False


    with open('routes.txt','r') as f:
        lines = f.readlines()
        while not finished(is_covered):
            i = 1
            for line in lines:
                splitted = line.strip().split(',')
                if not is_covered[i]:
                    if solution_covers(solution,line):
                        is_covered[i] = True
                    else:
                        best_score_of_line = get_best_router_of_line(dict(router_occurences),splitted)
                        print('Adding '+best_score_of_line[0]+' for line: '+str(i))
                        solution.append(best_score_of_line[0])
                        is_covered[i] = True
                i += 1
    f.close()

    print("Solution size: "+str(len(solution)))
    for router in solution:
        print(router)

